rule sig_20160831_5ac514f010bb55e4124568f21760d0cd {
  meta:
    description = "datamaliciousorder - file 20160831_5ac514f010bb55e4124568f21760d0cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c9957235931c96986f8890217f9c28e4a65796705e415417902024993e003ec"

  strings:
    $s1  = "aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfuck" ascii
    $s2  = "aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfuck" ascii
    $s3  = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfu" ascii
    $s4  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfu" ascii
    $s5  = "aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfuc" ascii
    $s6  = "aver!!!!!!Bishut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuckin" ascii
    $s7  = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfuc" ascii
    $s10 = "e-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s11 = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!Qf2shut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Fwshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!XEpshut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!KVj7shut-the-fuck-up-motherfu" ascii
    $s19 = "aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}