rule sig_20160831_24ef55e92deffa9740389a3e2dc5a037 {
  meta:
    description = "datamaliciousorder - file 20160831_24ef55e92deffa9740389a3e2dc5a037.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64dccac8ae2fe2b631abcec26295851f1cc633d0f24d1855c3d52e16fbc24bb3"

  strings:
    $s1  = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfucki" ascii
    $s3  = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfuckin" ascii
    $s4  = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfuck" ascii
    $s6  = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuc" ascii
    $s7  = "aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfuck" ascii
    $s8  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfu" ascii
    $s9  = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Iishut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfuckin" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s15 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuck" ascii
    $s16 = "aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfuc" ascii
    $s20 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}