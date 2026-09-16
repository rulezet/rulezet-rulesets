rule _20160921_b5efb4ba3e712545d64a2d00b3dcd76e_20160921_d4e094c14df4_4032 {
  meta:
    description = "datamaliciousorder - from files 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js, 20160921_d4e094c14df45f61de0e1163f51e03e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"
    hash2       = "2877b2ace685858babd88dd0ef1659f49f21c3f8b907e5b3889ec46bf3a7104a"

  strings:
    $s1 = "function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){re" ascii
    $s2 = "rn \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(fun" ascii
    $s3 = "t\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function f" ascii
    $s4 = "(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){ret" ascii
    $s5 = "n \"Et\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(fun" ascii
    $s6 = "nction fuck(){return \"UOe\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}