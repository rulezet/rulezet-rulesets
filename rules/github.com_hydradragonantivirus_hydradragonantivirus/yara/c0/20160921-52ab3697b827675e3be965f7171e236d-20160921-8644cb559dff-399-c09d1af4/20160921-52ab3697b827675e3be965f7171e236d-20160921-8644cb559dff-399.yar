rule _20160921_52ab3697b827675e3be965f7171e236d_20160921_8644cb559dff_399 {
  meta:
    description = "datamaliciousorder - from files 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_c4afaa1e41efa7633248f1941bda4010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash2       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash3       = "64cdab0c251929ea414823662957bad76268a8398b0c708715609f37e7070a69"

  strings:
    $s1  = "ck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\"" ascii
    $s2  = "eturn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(" ascii
    $s3  = "k(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";" ascii
    $s4  = "urn \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s5  = "ck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\"" ascii
    $s6  = "urn \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(" ascii
    $s7  = "\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function" ascii
    $s8  = "s\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"PDf\";})(),(function " ascii
    $s9  = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"" ascii
    $s10 = "n \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(fun" ascii
    $s11 = "n \"XFd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s12 = "n fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s13 = "n fuck(){return \"PDf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"" ascii
    $s14 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retu" ascii
    $s15 = "n \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(f" ascii
    $s16 = "rn \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(" ascii
    $s17 = "uck(){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf" ascii
    $s18 = "(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"RAi\";})(),(function fuck" ascii
    $s19 = "ion fuck(){return \"Ve\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s20 = "eturn \"CTm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}