rule Imploder1_04__BoB_Team_PEiD {
  meta:
    author      = "PEiD"
    description = "Imploder 1.04 -> BoB / Team PEiD"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { 60 E8 C8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

  condition:
    $a0
}