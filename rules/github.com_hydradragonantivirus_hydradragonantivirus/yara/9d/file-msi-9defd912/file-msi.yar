rule file_msi {
  meta:
    description   = "Finds Microsoft Installer (.msi) files"
    last_modified = "2024-03-02"
    author        = "@petermstewart"
    DaysofYara    = "62/100"

  strings:
    $magic = { d0 cf 11 e0 a1 b1 1a e1 }
    $clsid = { 84 10 0c 00 00 00 00 00 c0 00 00 00 00 00 00 46 }

  condition:
    $magic at 0 and
    $clsid
}