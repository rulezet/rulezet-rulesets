rule _20160921_3bd7e22bf0147340b20eeb7a825cb9a1_20160921_50544c5faa56_3680 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_50544c5faa56c0c9ed1c35075bafc583.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash2       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"

  strings:
    $s1 = "\"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s2 = "nction fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){retu" ascii
    $s3 = "ck(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm" ascii
    $s4 = "n fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s5 = "n \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Za\";})(),(func" ascii
    $s6 = "Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}