rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_8471da3d602d_4745 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"

  strings:
    $s1 = " \"DNa\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s2 = "urn \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Rh\";})(),(f" ascii
    $s3 = ";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000" ascii
    $s4 = "f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Rh" ascii
    $s5 = "GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKp\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}