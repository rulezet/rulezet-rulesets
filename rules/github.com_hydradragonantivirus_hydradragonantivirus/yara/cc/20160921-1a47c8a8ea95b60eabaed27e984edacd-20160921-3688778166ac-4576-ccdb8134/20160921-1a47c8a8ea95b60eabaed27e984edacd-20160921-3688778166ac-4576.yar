rule _20160921_1a47c8a8ea95b60eabaed27e984edacd_20160921_3688778166ac_4576 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_3688778166acb8f4f21b3c1d67ada442.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash2       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"
    hash3       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1 = "k(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";" ascii
    $s2 = "fuck(){return \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh" ascii
    $s3 = "nction fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){retu" ascii
    $s4 = " fuck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm" ascii
    $s5 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}