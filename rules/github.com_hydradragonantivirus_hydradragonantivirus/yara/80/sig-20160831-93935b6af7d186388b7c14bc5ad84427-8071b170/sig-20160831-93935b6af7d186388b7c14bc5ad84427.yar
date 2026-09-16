rule sig_20160831_93935b6af7d186388b7c14bc5ad84427 {
  meta:
    description = "datamaliciousorder - file 20160831_93935b6af7d186388b7c14bc5ad84427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ad623dd3109b5d89f52a42609e786adb2d7de888dc98730e1940bfd84d6e153"

  strings:
    $s1  = "aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!APzshut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s6  = "aver!!!!!!BDx7shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuck" ascii
    $s7  = "aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuckin" ascii
    $s8  = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfu" ascii
    $s10 = "aver!!!!!!Bishut-the-fuck-up-motherfucking-aver!!!!!!Pw2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s11 = "aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfu" ascii
    $s15 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfuc" ascii
    $s16 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuckin" ascii
    $s18 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s20 = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}