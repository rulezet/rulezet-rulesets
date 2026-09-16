import "pe"
rule alloy {
  meta:
    author      = "PEiD"
    description = "Alloy 1.x.2000 -> Prakash Gautam"
    group       = "302"
    function    = "0"

  strings:
    $a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 46 23 40 ?? 0B }

  condition:
    $a0 at pe.entry_point
}