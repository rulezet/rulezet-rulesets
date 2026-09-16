rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160921_e30a7fc515c8_3615 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"

  strings:
    $s1 = "\"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s2 = "000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu" ascii
    $s3 = "Ij\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(functio" ascii
    $s4 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s5 = "rn \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(fu" ascii
    $s6 = "){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}