rule realbasic {
  meta:
    author      = "PEiD"
    description = "REALBasic"
    group       = "555"
    function    = "0"

  strings:
    $a0 = { 55 89 E5 6A FF 68 78 FC 58 00 68 50 D9 53 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 50 53 83 }

  condition:
    $a0
}