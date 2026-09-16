rule _20160921_510713862e5c8c05841e5272407127f3_20160921_a160e4a38580_219 {
  meta:
    description = "datamaliciousorder - from files 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash2       = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"
    hash3       = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1  = "return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s2  = "rn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(fu" ascii
    $s3  = "fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo" ascii
    $s4  = ";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ai\";})(),(function fuck" ascii
    $s5  = "){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})" ascii
    $s6  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd" ascii
    $s7  = "rn \"PDf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s8  = "urn \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s9  = "uck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"RAi" ascii
    $s10 = "(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Ai\";})(),(function fuck()" ascii
    $s11 = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s12 = " fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"I" ascii
    $s13 = "tion fuck(){return \"AUx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return" ascii
    $s14 = "urn \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jh\";})(),(fu" ascii
    $s15 = "ck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"ADy" ascii
    $s16 = "o\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function" ascii
    $s17 = "function fuck(){return \"Av\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){ret" ascii
    $s18 = "){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";}" ascii
    $s19 = "tion fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s20 = "(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"RAi\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}