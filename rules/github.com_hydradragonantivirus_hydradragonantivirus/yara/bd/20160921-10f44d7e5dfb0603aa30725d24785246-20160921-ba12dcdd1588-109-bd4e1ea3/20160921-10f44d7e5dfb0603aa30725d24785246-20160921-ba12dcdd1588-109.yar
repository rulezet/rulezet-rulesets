rule _20160921_10f44d7e5dfb0603aa30725d24785246_20160921_ba12dcdd1588_109 {
  meta:
    description = "datamaliciousorder - from files 20160921_10f44d7e5dfb0603aa30725d24785246.js, 20160921_ba12dcdd1588a0048542bf1b103073ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ded66def256e0559ce1d6d20e6f8663edec045a58bb8ef0ec1038fbd91f7c7c1"
    hash2       = "18a1f3c65d9893a27783cb78ff5cd36c757196e35be1977f03c68231e20d9b44"

  strings:
    $s1  = "{return \"DRx\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"ZVi\";}" ascii
    $s2  = "k(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\"" ascii
    $s3  = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return " ascii
    $s4  = "ck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\"" ascii
    $s5  = "on fuck(){return \"Zy\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"" ascii
    $s6  = "Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s7  = "on fuck(){return \"Xw\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"X" ascii
    $s8  = "Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(functio" ascii
    $s9  = ";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"YAv\";})(),(function fuc" ascii
    $s10 = "turn \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"MIl\";})()," ascii
    $s11 = ",(function fuck(){return \"Xw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){r" ascii
    $s12 = "nction fuck(){return \"GWo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s13 = "n fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"" ascii
    $s14 = "uck(){return \"GWo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg" ascii
    $s15 = "rn \"Jo\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s16 = "o\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(functio" ascii
    $s17 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){ret" ascii
    $s18 = "tion fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii
    $s19 = "urn \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(fu" ascii
    $s20 = "k(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"GNm\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}