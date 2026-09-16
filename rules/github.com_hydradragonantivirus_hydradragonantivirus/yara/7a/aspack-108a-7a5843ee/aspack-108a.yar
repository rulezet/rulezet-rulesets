rule aspack_108a {
  meta:
    author      = "PEiD"
    description = "ASPack 1.08.00 - 1.08.04 -> Alexey Solodovnikov"
    group       = "105"
    function    = "1"

  strings:
    $a0 = { 90 75 01 ?? E9 }

  condition:
    $a0
}