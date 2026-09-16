rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_297b9b66086a_4746 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash3       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"

  strings:
    $s1 = "urn \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})()," ascii
    $s2 = "unction f000(){return \"MMz\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){retu" ascii
    $s3 = "f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s4 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"MMz\";})()" ascii
    $s5 = "n \"MMz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}