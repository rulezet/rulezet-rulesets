rule _20160921_20daf816cda5af37e984359023f15db2_20160921_510713862e5c_815 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_510713862e5c8c05841e5272407127f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"

  strings:
    $s1  = " fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"I" ascii
    $s2  = "{return \"Ve\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})" ascii
    $s3  = "){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";}" ascii
    $s4  = "\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s5  = " \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(func" ascii
    $s6  = "rn \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s7  = "uck(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu" ascii
    $s8  = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Sx\";})(),(function" ascii
    $s9  = "uck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s10 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Na\";})(),(function fuck" ascii
    $s11 = "uck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\"" ascii
    $s12 = "k(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";" ascii
    $s13 = " \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"FJs\";})(),(fun" ascii
    $s14 = ",(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){" ascii
    $s15 = ",(function fuck(){return \"SUi\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s16 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ot\";})(),(function" ascii
    $s17 = "})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s18 = "tion fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s19 = "){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})" ascii
    $s20 = "on fuck(){return \"Ai\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}