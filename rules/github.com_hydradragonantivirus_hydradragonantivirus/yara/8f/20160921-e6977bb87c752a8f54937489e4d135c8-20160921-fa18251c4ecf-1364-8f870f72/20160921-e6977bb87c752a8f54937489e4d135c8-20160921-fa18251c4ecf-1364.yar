rule _20160921_e6977bb87c752a8f54937489e4d135c8_20160921_fa18251c4ecf_1364 {
  meta:
    description = "datamaliciousorder - from files 20160921_e6977bb87c752a8f54937489e4d135c8.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"
    hash2       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1  = "on fuck(){return \"Yk\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"" ascii
    $s2  = "Tm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(functio" ascii
    $s3  = "){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"Cs\";})(" ascii
    $s4  = "ck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"CCb\"" ascii
    $s5  = "tion fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){retur" ascii
    $s6  = "){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})" ascii
    $s7  = "function fuck(){return \"YQt\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){re" ascii
    $s8  = "function fuck(){return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){re" ascii
    $s9  = "CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"MOj\";})(),(funct" ascii
    $s10 = " \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Vf\";})(),(fun" ascii
    $s11 = "rn \"BGe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(" ascii
    $s12 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return" ascii
    $s13 = "unction fuck(){return \"Jh\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s14 = "ck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr" ascii
    $s15 = "k(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ug\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}