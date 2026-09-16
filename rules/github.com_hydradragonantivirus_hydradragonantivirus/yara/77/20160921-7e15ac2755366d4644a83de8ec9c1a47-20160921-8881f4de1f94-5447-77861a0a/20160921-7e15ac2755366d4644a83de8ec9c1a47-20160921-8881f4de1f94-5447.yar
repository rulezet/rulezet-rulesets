rule _20160921_7e15ac2755366d4644a83de8ec9c1a47_20160921_8881f4de1f94_5447 {
  meta:
    description = "datamaliciousorder - from files 20160921_7e15ac2755366d4644a83de8ec9c1a47.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"
    hash2       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"

  strings:
    $s1 = "on fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"" ascii
    $s2 = "turn \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s3 = "){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})()" ascii
    $s4 = "\"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(functi" ascii
    $s5 = ",(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}