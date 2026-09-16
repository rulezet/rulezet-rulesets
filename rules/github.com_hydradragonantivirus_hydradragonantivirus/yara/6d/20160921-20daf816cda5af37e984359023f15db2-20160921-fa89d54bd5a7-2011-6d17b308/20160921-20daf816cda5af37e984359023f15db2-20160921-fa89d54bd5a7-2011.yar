rule _20160921_20daf816cda5af37e984359023f15db2_20160921_fa89d54bd5a7_2011 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = "(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck()" ascii
    $s2 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(funct" ascii
    $s3 = "nction fuck(){return \"Cd\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Za\";})(),(function fuck(){retur" ascii
    $s4 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"GWo\"" ascii
    $s5 = "})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ADy\";})(),(function fu" ascii
    $s6 = "unction fuck(){return \"YQt\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s7 = "turn \"Jo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Cd\";})(),(f" ascii
    $s8 = ",(function fuck(){return \"Sx\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s9 = "\"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}