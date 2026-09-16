rule sig_20160831_db63cc91a04656b05ee77b853a2f9f89 {
  meta:
    description = "datamaliciousorder - file 20160831_db63cc91a04656b05ee77b853a2f9f89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c772882121c2fea4d25a08ae3e25868156b172ceabe1717986455492caf988d8"

  strings:
    $s1  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qsshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s2  = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s4  = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!Ug6shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfuckin" ascii
    $s8  = "aver!!!!!!APzshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfuck" ascii
    $s14 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s15 = "aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s16 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s17 = "aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Iishut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s20 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}