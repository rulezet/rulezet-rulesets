rule _20160921_063094039ef79437a260d3dde960797a_20160921_32a3b245a67c_574 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash3       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"

  strings:
    $s1  = "ion fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck()" ascii
    $s3  = "unction fuck(){return \"Za\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s4  = "ck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Ot\"" ascii
    $s5  = "return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";})()," ascii
    $s6  = "tion fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retur" ascii
    $s7  = ",(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){re" ascii
    $s8  = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){ret" ascii
    $s9  = "rn \"MBg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})(),(f" ascii
    $s10 = "n fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"I" ascii
    $s11 = "nction fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s12 = "ion fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s13 = "){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})" ascii
    $s14 = "return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Qh\";})(" ascii
    $s15 = "k(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\"" ascii
    $s16 = "return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(" ascii
    $s17 = "ck(){return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs" ascii
    $s18 = "})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"XFd\";})(),(function fuc" ascii
    $s19 = "ck(){return \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq" ascii
    $s20 = "(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}