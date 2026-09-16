rule sig_20160831_f6b81c220540a19e01d5c5c683cae909 {
  meta:
    description = "datamaliciousorder - file 20160831_f6b81c220540a19e01d5c5c683cae909.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0eb8c6622bdda43010d6bc7badf840458af16baf8b16fb396f80162971bf9837"

  strings:
    $s1  = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuck" ascii
    $s2  = "aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Qf2shut-the-fuck-up-motherfuck" ascii
    $s3  = "he-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s4  = "aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfuckin" ascii
    $s5  = "aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!Ya2shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s7  = "aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuckin" ascii
    $s8  = "aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfuck" ascii
    $s9  = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuc" ascii
    $s13 = "he-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s14 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking" ascii
    $s15 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!BDx7shut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfuc" ascii
    $s18 = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}