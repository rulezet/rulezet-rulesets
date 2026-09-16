rule pbasic702 {
  meta:
    author      = "PEiD"
    description = "PowerBasic 7.02"
    group       = "117"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 53 56 57 BB ?? ?? ?? ?? 66 2E F7 ?? ?? ?? ?? 00 04 00 0F 85 }

  condition:
    $a0
}