rule _20160921_8aaa596582e26eec62319f01660d922b_20160921_e30a7fc515c8_5504 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "ction f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s2 = "ion f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s3 = "nction f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return" ascii
    $s4 = "ction f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii
    $s5 = "ion f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}