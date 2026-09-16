rule _20160921_0e1bfa63bcb2804e89834c330285643e_20160921_ad1fccc6910b_18 {
  meta:
    description = "datamaliciousorder - from files 20160921_0e1bfa63bcb2804e89834c330285643e.js, 20160921_ad1fccc6910bd9c4a47aa9bd3e9239da.js, 20160921_e39622eeb1da8fbbf03ca86989251a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d58b57cb825244d35e22402fcf08c9ababcc51eb72a7913c47dbb2143171df32"
    hash2       = "a49fc1cb85eaa58b7c63197e9fd25224f63dcb6c86b906933f698898634ead3e"
    hash3       = "e0b1660f1c95284f1a0f8062a1f16e26aa3d58e3fa4cf47fc04824d02b754a56"

  strings:
    $s1  = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ug\";" ascii
    $s2  = "Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(functio" ascii
    $s3  = "k(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Wo0" ascii
    $s4  = "k(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"LGo\";" ascii
    $s5  = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(funct" ascii
    $s6  = "ction fuck(){return \"Et\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s7  = "return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(" ascii
    $s8  = "ion fuck(){return \"Nm\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return " ascii
    $s9  = "function fuck(){return \"Nm\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s10 = "turn \"LGo\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(" ascii
    $s11 = ")(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"IOs\";})(),(function fuc" ascii
    $s12 = "n \"XHj\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"MOj\";})(),(fu" ascii
    $s13 = "Pu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s14 = "Ts\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Ot\";})(),(function" ascii
    $s15 = "(){return \"UOe\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";" ascii
    $s16 = " \"PDf\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s17 = "(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IPu\";}" ascii
    $s18 = "ction fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s19 = "urn \"Jh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(fu" ascii
    $s20 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}