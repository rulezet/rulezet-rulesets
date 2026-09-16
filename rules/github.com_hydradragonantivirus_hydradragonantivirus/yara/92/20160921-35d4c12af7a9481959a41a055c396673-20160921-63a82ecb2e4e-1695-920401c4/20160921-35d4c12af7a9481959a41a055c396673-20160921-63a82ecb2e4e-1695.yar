rule _20160921_35d4c12af7a9481959a41a055c396673_20160921_63a82ecb2e4e_1695 {
  meta:
    description = "datamaliciousorder - from files 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash2       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"

  strings:
    $s1  = "turn \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";})()," ascii
    $s2  = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s3  = "rn \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(fu" ascii
    $s4  = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s5  = "tion fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s6  = "{return \"IPu\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";}" ascii
    $s7  = "ck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\"" ascii
    $s8  = "rn \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(f" ascii
    $s9  = "ck(){return \"CTm\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";" ascii
    $s10 = "n fuck(){return \"OQr\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii
    $s11 = "})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Dc\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}