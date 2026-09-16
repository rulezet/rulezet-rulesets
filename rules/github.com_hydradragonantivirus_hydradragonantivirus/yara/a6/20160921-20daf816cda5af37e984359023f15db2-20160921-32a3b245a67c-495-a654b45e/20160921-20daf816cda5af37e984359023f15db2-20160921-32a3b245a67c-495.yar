rule _20160921_20daf816cda5af37e984359023f15db2_20160921_32a3b245a67c_495 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js, 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_378cbd2e27643682973c633e59454f9f.js, 20160921_5c25506bc44b50a0c8028dec6521139d.js, 20160921_5cabcf77c626e288d5cbd9104a914ae8.js, 20160921_6db2cb585eb933d83d07b47d979b00ec.js, 20160921_6fabf8ef6df7ba14509fab6de95d721f.js, 20160921_70d636d209e6f109a21746567376cc81.js, 20160921_8c8c9fad8af659443108d1078847a668.js, 20160921_9b80c329004df146d978cb7b31b22c05.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js, 20160921_afb633ee817d9b15b91ed82a059939fc.js, 20160921_c694815b18c140f34c0f79f86106d901.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js, 20160921_dbc1b5f3d0381a2cf3968267e55b6f78.js, 20160921_e8d738510e4d2e0efb6c7aa18a7a58d8.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash3       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"
    hash4       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash5       = "8ce016002e44e1fbf4624122138e5a8b0261aff6487c52da0d644398da46a896"
    hash6       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"
    hash7       = "9493e4251106014081e4b141c6296c51b00c9ba7a799bcb978ea6226cd127d34"
    hash8       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"
    hash9       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"
    hash10      = "6e26044e7a07a5a675f3b388e6309b138b9e7a1aa61556485f444025164a158e"
    hash11      = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"
    hash12      = "d0ec644cd7307cbd280d369539e9834d3ad2ba0909b631b5a3640f8f6a1105d1"
    hash13      = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"
    hash14      = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"
    hash15      = "650c20b763cdd9e1631c1f76f67b04a911cfce7996c1e9928b9c3b7fe1f8e7e5"
    hash16      = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"
    hash17      = "e37cb576da589586ca091f887f2d941f81f58c7a8c3974b4e11928357dfee825"
    hash18      = "e1cd4a36522d2ad8fc8435b6cb64d8e572d8b31d4203885fa375f539a3ea7891"
    hash19      = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1  = " \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XCr\";})(),(fun" ascii
    $s2  = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Et\";})(),(function fuc" ascii
    $s3  = "\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function " ascii
    $s4  = ",(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){r" ascii
    $s5  = "(function fuck(){return \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){re" ascii
    $s6  = "ion fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return " ascii
    $s7  = "})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(" ascii
    $s8  = ")(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Wn\";})(),(function fuck(" ascii
    $s9  = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){re" ascii
    $s10 = "(function fuck(){return \"ZWu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){r" ascii
    $s11 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii
    $s12 = "o\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s13 = "n \"ZLd\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(f" ascii
    $s14 = ";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GJx\";})(),(function fu" ascii
    $s15 = "urn \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Jg\";})(),(fun" ascii
    $s16 = "(function fuck(){return \"Et\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){re" ascii
    $s17 = "u\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function f" ascii
    $s18 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){retu" ascii
    $s19 = "turn \"Ve\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s20 = "on fuck(){return \"Xw\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}