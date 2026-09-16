rule sig_20160831_2cbcf2785b1e9cf51bbd967fb8cde785 {
  meta:
    description = "datamaliciousorder - file 20160831_2cbcf2785b1e9cf51bbd967fb8cde785.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27944edd6f7d94cbf790dac484333bdf4c6f821f5adb420a496c51c587224474"

  strings:
    $s1  = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!Ug6shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfuckin" ascii
    $s8  = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s9  = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s10 = "he-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s11 = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking" ascii
    $s12 = "aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfuck" ascii
    $s15 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s16 = "aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Iishut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfu" ascii
    $s20 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}