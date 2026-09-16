rule _20160921_1c739a510b202fd8658c1445b926e28b_20160921_d88b1be24c58_1035 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_d88b1be24c583b3513de141e173a825f.js, 20160921_dd42e850834f3af27a08edf609a699b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash2       = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"
    hash3       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"

  strings:
    $s1  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"" ascii
    $s2  = "\"GJx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s3  = "Jx\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s4  = " \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(fu" ascii
    $s5  = "(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s6  = " fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv" ascii
    $s7  = "(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){r" ascii
    $s8  = "uck(){return \"GJx\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s9  = "nction fuck(){return \"XHj\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s10 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IOs\";})" ascii
    $s11 = "ion fuck(){return \"GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s12 = ",(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){r" ascii
    $s13 = "k(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s14 = " \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(fu" ascii
    $s15 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(func" ascii
    $s16 = "\"YAv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s17 = "){return \"MUs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s18 = "k(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}