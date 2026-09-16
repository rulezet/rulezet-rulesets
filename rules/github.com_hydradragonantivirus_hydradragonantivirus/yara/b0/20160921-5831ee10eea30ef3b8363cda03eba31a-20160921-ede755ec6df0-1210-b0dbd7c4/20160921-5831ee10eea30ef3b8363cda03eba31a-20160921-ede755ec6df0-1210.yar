rule _20160921_5831ee10eea30ef3b8363cda03eba31a_20160921_ede755ec6df0_1210 {
  meta:
    description = "datamaliciousorder - from files 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash2       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"

  strings:
    $s1  = "Cr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s2  = "tion fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s3  = "),(function fuck(){return \"XHj\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s4  = "ck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"YQt" ascii
    $s5  = "(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\"" ascii
    $s6  = "(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck()" ascii
    $s7  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return " ascii
    $s8  = "rn \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s9  = "\"Wo\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Np\";})(),(funct" ascii
    $s10 = "turn \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s11 = "uck(){return \"Xw\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw\"" ascii
    $s12 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"" ascii
    $s13 = "nction fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retur" ascii
    $s14 = "(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\"" ascii
    $s15 = "function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retu" ascii
    $s16 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZLd\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}