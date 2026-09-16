rule sig_20160831_50f009798c602f6a2efcc93200734068 {
  meta:
    description = "datamaliciousorder - file 20160831_50f009798c602f6a2efcc93200734068.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "549e332f56426f2e1c61855869710f3929c9f3f4d927dba655572562b0f01779"

  strings:
    $s1  = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfuc" ascii
    $s2  = "aver!!!!!!KVj7shut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfuc" ascii
    $s3  = "aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuc" ascii
    $s6  = "aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s7  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuc" ascii
    $s8  = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s9  = "aver!!!!!!Qf2shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Le6shut-the-fuck-up-motherfucking-aver!!!!!!Pw2shut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfuc" ascii
    $s12 = "aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s16 = "he-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s17 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfuck" ascii
    $s18 = "-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s19 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}