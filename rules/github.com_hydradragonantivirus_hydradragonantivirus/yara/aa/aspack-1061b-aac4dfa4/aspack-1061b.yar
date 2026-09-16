import "pe"
rule aspack_1061b {
  meta:
    author      = "PEiD"
    description = "ASPack 1.061b -> Alexey Solodovnikov"
    group       = "100"
    function    = "0"

  strings:
    $a0 = { 60 E8 00 00 00 00 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }

  condition:
    $a0 at pe.entry_point
}