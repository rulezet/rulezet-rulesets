rule _20160921_93920c7f8d8dcef0135d270226e913f5_20160921_c42fb5c75aea_3090 {
  meta:
    description = "datamaliciousorder - from files 20160921_93920c7f8d8dcef0135d270226e913f5.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"
    hash2       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash3       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"

  strings:
    $s1 = "n fuck(){return \"EHo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"O" ascii
    $s2 = "return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Wo\";})()," ascii
    $s3 = "unction fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){retu" ascii
    $s4 = "ion fuck(){return \"LLv\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s5 = "),(function fuck(){return \"Xw\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){" ascii
    $s6 = ",(function fuck(){return \"ZLd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){" ascii
    $s7 = "\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"LLv\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}