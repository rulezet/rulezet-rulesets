rule _20160921_052f92106046138b3c82e05878edd3a8_20160921_0d4a04b6f479_154 {
  meta:
    description = "datamaliciousorder - from files 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash2       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash3       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash4       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash5       = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"
    hash6       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"" ascii
    $s2  = "\"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(functio" ascii
    $s3  = ")(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck" ascii
    $s4  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii
    $s5  = "rn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Nm\";})(),(fu" ascii
    $s6  = "{return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Jh\";})()" ascii
    $s7  = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"UXf\";})(),(" ascii
    $s8  = ",(function fuck(){return \"DWe\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){" ascii
    $s9  = "k(){return \"Yk\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";" ascii
    $s10 = "n \"Xw\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Xw\";})(),(func" ascii
    $s11 = "fuck(){return \"Xg\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\"" ascii
    $s12 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){ret" ascii
    $s13 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function " ascii
    $s14 = "\"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(funct" ascii
    $s15 = "(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";" ascii
    $s16 = "{return \"XHj\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Xw\";})" ascii
    $s17 = "turn \"Na\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s18 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"MIl\";})()" ascii
    $s19 = "(){return \"MIl\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";" ascii
    $s20 = " fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"X" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}