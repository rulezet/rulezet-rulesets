rule packman0001 {
  meta:
    author      = "PEiD"
    description = "Packman 0.0.0.1 -> Bubbasoft"
    group       = "444"
    function    = "0"

  strings:
    $a0 = { 60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 ?? ?? ?? FF 8D B0 74 01 00 00 8D 4E F6 48 C6 40 FB E9 8D 93 ?? ?? ?? 00 2B D0 89 50 FC 8D 93 54 01 00 00 E9 9A 00 00 00 83 C2 04 03 FB 51 D1 C7 D1 EF 0F 83 84 00 00 00 53 55 52 B2 80 8B D9 }

  condition:
    $a0
}