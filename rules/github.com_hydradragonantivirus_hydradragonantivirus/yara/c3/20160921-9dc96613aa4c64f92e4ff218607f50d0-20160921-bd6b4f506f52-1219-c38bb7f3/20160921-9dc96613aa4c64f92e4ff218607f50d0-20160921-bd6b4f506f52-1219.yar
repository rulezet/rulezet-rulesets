rule _20160921_9dc96613aa4c64f92e4ff218607f50d0_20160921_bd6b4f506f52_1219 {
  meta:
    description = "datamaliciousorder - from files 20160921_9dc96613aa4c64f92e4ff218607f50d0.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c272b2491e06062a7ec30effe81ff00903e7c91b1be85625b1fe6794546c7a"
    hash2       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"

  strings:
    $s1  = "Js\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function" ascii
    $s2  = ",(function fuck(){return \"MIl\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s3  = "tion fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s4  = "Qh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s5  = "\"GJx\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s6  = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Mw" ascii
    $s7  = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retur" ascii
    $s8  = "Et\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(functi" ascii
    $s9  = "Pu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"USf\";})(),(function" ascii
    $s10 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"" ascii
    $s11 = "uck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"XCr" ascii
    $s12 = "})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fu" ascii
    $s13 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Jh\";})(),(fu" ascii
    $s14 = "n fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"" ascii
    $s15 = "ction fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s16 = "rn \"PDf\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}