rule _20160921_3282034bab74b3776acf585e8adfca92_20160921_766f6fcbd2a9_3607 {
  meta:
    description = "datamaliciousorder - from files 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash2       = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"

  strings:
    $s1 = "u\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ar\";})(),(function" ascii
    $s2 = "nction fuck(){return \"Ve\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s3 = "unction fuck(){return \"Hs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){retur" ascii
    $s4 = ";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"RAi\";})(),(function fu" ascii
    $s5 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Wo\";})(),(function fuck(" ascii
    $s6 = "tion fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}