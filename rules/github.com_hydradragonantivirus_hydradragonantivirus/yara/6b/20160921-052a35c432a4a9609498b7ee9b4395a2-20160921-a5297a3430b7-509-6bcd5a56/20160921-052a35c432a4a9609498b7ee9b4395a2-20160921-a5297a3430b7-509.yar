rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_a5297a3430b7_509 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash3       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"
    hash4       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"
    hash5       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1  = "k(){return \"Vf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\"" ascii
    $s2  = "ion fuck(){return \"IOs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s3  = ")(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xw\";})(),(function fuck(" ascii
    $s4  = "unction fuck(){return \"EHo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){ret" ascii
    $s5  = "n \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Xg\";})(),(fun" ascii
    $s6  = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"XFd\";})(),(fun" ascii
    $s7  = "k(){return \"Xw\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";}" ascii
    $s8  = " \"Xw\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ik\";})(),(funct" ascii
    $s9  = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za\";})(),(function" ascii
    $s10 = "We\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s11 = "uck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"GNm" ascii
    $s12 = ";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuc" ascii
    $s13 = "){return \"Oh\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s14 = "{return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";}" ascii
    $s15 = " \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XCr\";})(),(fun" ascii
    $s16 = "n fuck(){return \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"" ascii
    $s17 = "nction fuck(){return \"Sx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s18 = "(){return \"Xw\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Pc\";}" ascii
    $s19 = ",(function fuck(){return \"Jo\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){r" ascii
    $s20 = "\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"UOe\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}