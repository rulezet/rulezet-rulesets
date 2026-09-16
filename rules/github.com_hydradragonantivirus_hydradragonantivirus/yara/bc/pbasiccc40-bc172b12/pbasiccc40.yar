rule pbasiccc40 {
  meta:
    author      = "PEiD"
    description = "PowerBASIC/CC 4.0"
    group       = "555"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 53 56 57 BB 00 ?? 40 00 66 2E F7 05 ?? ?? 40 00 04 00 75 05 E9 68 05 00 00 E9 6E 03 }

  condition:
    $a0
}