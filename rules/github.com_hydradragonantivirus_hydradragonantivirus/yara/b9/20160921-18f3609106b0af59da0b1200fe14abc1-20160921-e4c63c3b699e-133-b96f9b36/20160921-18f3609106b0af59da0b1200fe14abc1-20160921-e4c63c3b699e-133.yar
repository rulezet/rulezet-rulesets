rule _20160921_18f3609106b0af59da0b1200fe14abc1_20160921_e4c63c3b699e_133 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash2       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"

  strings:
    $s1  = "ction fuck(){return \"Ar\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){retur" ascii
    $s2  = ";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Xw\";})(),(function fu" ascii
    $s3  = "(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){re" ascii
    $s4  = "Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Yk\";})(),(function" ascii
    $s5  = "ion fuck(){return \"Ik\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s6  = "\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"PDf\";})(),(function f" ascii
    $s7  = "(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck" ascii
    $s8  = "){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";}" ascii
    $s9  = "function fuck(){return \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii
    $s10 = "),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){" ascii
    $s11 = "unction fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){re" ascii
    $s12 = "n fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"" ascii
    $s13 = "tion fuck(){return \"Wo\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return" ascii
    $s14 = "fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"I" ascii
    $s15 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Wo0\";})()" ascii
    $s16 = " fuck(){return \"Ot\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"I" ascii
    $s17 = "),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck()" ascii
    $s18 = "rn \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Av\";})(),(fun" ascii
    $s19 = ",(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s20 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"KVh\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}