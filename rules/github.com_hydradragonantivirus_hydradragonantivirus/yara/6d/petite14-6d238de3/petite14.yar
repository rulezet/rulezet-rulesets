import "pe"
rule petite14 {
  meta:
    author      = "PEiD"
    description = "PEtite 1.4 -> Ian Luck"
    group       = "159"
    function    = "0"

  strings:
    $a0 = { 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B CC }

  condition:
    $a0 at pe.entry_point
}