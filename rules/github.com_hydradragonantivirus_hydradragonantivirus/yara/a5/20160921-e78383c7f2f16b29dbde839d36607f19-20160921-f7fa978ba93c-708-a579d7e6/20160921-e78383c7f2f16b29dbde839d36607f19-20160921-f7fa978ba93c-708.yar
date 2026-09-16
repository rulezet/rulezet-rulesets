rule _20160921_e78383c7f2f16b29dbde839d36607f19_20160921_f7fa978ba93c_708 {
  meta:
    description = "datamaliciousorder - from files 20160921_e78383c7f2f16b29dbde839d36607f19.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"
    hash2       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1  = ")(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(),(function fuck" ascii
    $s2  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ik\";})(),(function fuck()" ascii
    $s3  = "ck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s4  = "unction fuck(){return \"Jo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s5  = "rn \"MIl\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"OPz\";})(),(" ascii
    $s6  = " fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"" ascii
    $s7  = "nction fuck(){return \"XHj\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retur" ascii
    $s8  = " fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"O" ascii
    $s9  = "function fuck(){return \"GWo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){re" ascii
    $s10 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return" ascii
    $s11 = "k(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DRx\";" ascii
    $s12 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})()," ascii
    $s13 = ";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ot\";})(),(function fuc" ascii
    $s14 = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Mw" ascii
    $s15 = "\"Sx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"CCb\";})(),(func" ascii
    $s16 = "i\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Py\";})(),(function" ascii
    $s17 = "function fuck(){return \"MBg\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){ret" ascii
    $s18 = "n \"YAv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(fun" ascii
    $s19 = "return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})" ascii
    $s20 = "on fuck(){return \"GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}