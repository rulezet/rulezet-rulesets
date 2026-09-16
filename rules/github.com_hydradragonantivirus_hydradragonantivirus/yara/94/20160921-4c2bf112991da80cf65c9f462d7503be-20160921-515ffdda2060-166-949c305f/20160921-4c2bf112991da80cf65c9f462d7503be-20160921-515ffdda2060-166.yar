rule _20160921_4c2bf112991da80cf65c9f462d7503be_20160921_515ffdda2060_166 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash2       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash3       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash4       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"

  strings:
    $s1  = "(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";}" ascii
    $s2  = "fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo" ascii
    $s3  = "uck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Av" ascii
    $s4  = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"W" ascii
    $s5  = "We\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"MOj\";})(),(functio" ascii
    $s6  = "rn \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s7  = "unction fuck(){return \"Zy\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s8  = "return \"Xw\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s9  = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retu" ascii
    $s10 = "n fuck(){return \"Wo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s11 = "ck(){return \"DWe\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx" ascii
    $s12 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"" ascii
    $s13 = " \"We\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s14 = "unction fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){ret" ascii
    $s15 = "{return \"Ve\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})" ascii
    $s16 = "ck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\"" ascii
    $s17 = "v\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Nm\";})(),(function" ascii
    $s18 = "tion fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return" ascii
    $s19 = "return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})" ascii
    $s20 = "{return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}