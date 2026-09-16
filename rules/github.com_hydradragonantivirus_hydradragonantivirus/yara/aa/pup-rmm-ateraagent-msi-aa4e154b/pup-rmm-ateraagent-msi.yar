rule PUP_RMM_AteraAgent_msi {
  meta:
    description   = "Matches strings found in Atera Agent remote management tool installer, often abused for unauthorised access."
    last_modified = "2024-03-04"
    author        = "@petermstewart"
    DaysofYara    = "64/100"
    sha256        = "91d9c73b804aae60057aa93f4296d39ec32a01fe8201f9b73f979d9f9e4aea8b"

  strings:
    $magic = { d0 cf 11 e0 a1 b1 1a e1 }
    $clsid = { 84 10 0c 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
    $a1    = "AteraAgent"
    $a2    = "This installer database contains the logic and data required to install AteraAgent."

  condition:
    $magic at 0 and
    all of them
}