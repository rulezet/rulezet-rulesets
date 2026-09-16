import "pe"
rule petite12 {
  meta:
    author      = "PEiD"
    description = "PEtite 1.2 -> Ian Luck"
    group       = "159"
    function    = "0"

  strings:
    $a0 = { 9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }

  condition:
    $a0 at pe.entry_point
}