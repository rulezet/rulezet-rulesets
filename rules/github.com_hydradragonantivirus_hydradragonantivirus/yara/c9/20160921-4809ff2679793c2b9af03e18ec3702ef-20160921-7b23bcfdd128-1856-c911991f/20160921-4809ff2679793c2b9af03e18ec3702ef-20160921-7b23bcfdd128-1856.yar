rule _20160921_4809ff2679793c2b9af03e18ec3702ef_20160921_7b23bcfdd128_1856 {
  meta:
    description = "datamaliciousorder - from files 20160921_4809ff2679793c2b9af03e18ec3702ef.js, 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"
    hash2       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"

  strings:
    $s1  = "turn \"Ot\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s2  = " \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Mw\";})(),(fun" ascii
    $s3  = "return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})()" ascii
    $s4  = ",(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck()" ascii
    $s5  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"DR" ascii
    $s6  = "unction fuck(){return \"EHo\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s7  = "){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";}" ascii
    $s8  = ",(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){r" ascii
    $s9  = "tion fuck(){return \"Vf\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return " ascii
    $s10 = "w\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}