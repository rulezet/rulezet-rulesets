rule _20160921_2b38530ecae3735e98453e56dd7a0292_20160921_e26fc4dc1cce_3570 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b38530ecae3735e98453e56dd7a0292.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f1595f803e301ed13d99315b244aac664f908c0c0d8ab508c1d104bf7ae947"
    hash2       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(funct" ascii
    $s2 = "\"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(functi" ascii
    $s3 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"" ascii
    $s4 = "\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XFd\";})(),(function" ascii
    $s5 = "(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck()" ascii
    $s6 = "n \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}