rule sig_20160831_13a817e3d7c8f2a6a70a75519a9fa030 {
  meta:
    description = "datamaliciousorder - file 20160831_13a817e3d7c8f2a6a70a75519a9fa030.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04c5c64ab9945e37a24216bea94d1da9d6b928c70457e2160aa1702a5de7ef8e"

  strings:
    $s1  = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!XGx6shut-the-fuck-up-motherfucking-aver!!!!!!KVj7shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfu" ascii
    $s3  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfuc" ascii
    $s6  = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s7  = "aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfuc" ascii
    $s8  = "aver!!!!!!Ncshut-the-fuck-up-motherfucking-aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s10 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuc" ascii
    $s11 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfuckin" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Fwshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfuckin" ascii
    $s15 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfuck" ascii
    $s16 = "aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!Gcshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}