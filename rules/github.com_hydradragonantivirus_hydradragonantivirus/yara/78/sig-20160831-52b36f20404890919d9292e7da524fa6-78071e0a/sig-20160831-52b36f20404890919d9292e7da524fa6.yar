rule sig_20160831_52b36f20404890919d9292e7da524fa6 {
  meta:
    description = "datamaliciousorder - file 20160831_52b36f20404890919d9292e7da524fa6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff5114f0815ea53f239fc6d7bb66d4374b11771664e22ab320beeec90f272fc2"

  strings:
    $s1  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuck" ascii
    $s6  = "he-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s7  = "aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s10 = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Ncshut-the-fuck-up-motherfucking-aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!BZbshut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s14 = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking" ascii
    $s15 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ue0shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Dy2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}