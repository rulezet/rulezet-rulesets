rule _20160921_52ab3697b827675e3be965f7171e236d_20160921_8644cb559dff_117 {
  meta:
    description = "datamaliciousorder - from files 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash2       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"

  strings:
    $s1  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s2  = "unction fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s3  = "(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"PDf\";})(),(function fuck" ascii
    $s4  = "tion fuck(){return \"IOs\";})(),(function fuck(){return \"Az\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return" ascii
    $s5  = "){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DRx\";}" ascii
    $s6  = "unction fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){retu" ascii
    $s7  = "n fuck(){return \"YQt\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"" ascii
    $s8  = ";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuc" ascii
    $s9  = "uck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NK" ascii
    $s10 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ai\";})(),(function fuck" ascii
    $s11 = "n fuck(){return \"EHo\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"I" ascii
    $s12 = " \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s13 = "n \"Cd\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s14 = "eturn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"PDf\";})()" ascii
    $s15 = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){retur" ascii
    $s16 = " \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s17 = ";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fu" ascii
    $s18 = "ction fuck(){return \"XHj\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retu" ascii
    $s19 = "uck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj" ascii
    $s20 = "k(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}