rule _20160921_38347709a1c3747cfb23ae60221ea7bf_20160921_5f14ae6f169c_861 {
  meta:
    description = "datamaliciousorder - from files 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_5f14ae6f169c53d6d49523d1e13e4ab9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash2       = "270eb53363684986d2aef11b6b5bb4cd5c5cb316f626e41b627db2cf899b440e"

  strings:
    $s1  = "urn \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(f" ascii
    $s2  = "\"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(functi" ascii
    $s3  = ")(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck" ascii
    $s4  = "n fuck(){return \"Oh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s5  = "n \"Hs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"USf\";})(),(func" ascii
    $s6  = "on fuck(){return \"PDf\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"" ascii
    $s7  = "rn \"EHo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s8  = "nction fuck(){return \"YQt\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){retu" ascii
    $s9  = "ction fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s10 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){ret" ascii
    $s11 = "fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"E" ascii
    $s12 = "(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ve\";}" ascii
    $s13 = "tion fuck(){return \"Jo\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return" ascii
    $s14 = "{return \"Jo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s15 = "),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Np\";})(),(function fuck()" ascii
    $s16 = "on fuck(){return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return " ascii
    $s17 = "fuck(){return \"Et\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MO" ascii
    $s18 = "){return \"Qh\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})" ascii
    $s19 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"D" ascii
    $s20 = "rn \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"KVh\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}