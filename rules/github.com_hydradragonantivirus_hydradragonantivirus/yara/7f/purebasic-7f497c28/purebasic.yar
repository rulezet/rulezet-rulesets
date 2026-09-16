rule purebasic {
  meta:
    author      = "PEiD"
    description = "PureBasic -> Neil Hodgson - needs to be added"
    group       = "444"
    function    = "0"

  strings:
    $a0 = { 6A 00 ?? ?? ?? ?? ?? A3 ?? ?? 41 00 E8 ?? ?? ?? 00 6A 0A 50 6A 00 FF 35 ?? ?? 41 00 E8 07 00 00 00 50 E8 ?? ?? ?? 00 CC 68 ?? 00 00 00 68 00 00 00 00 68 ?? ?? 41 00 E8 ?? ?? 00 00 83 C4 0C 8B 44 24 04 A3 ?? ?? 41 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 }

  condition:
    $a0
}