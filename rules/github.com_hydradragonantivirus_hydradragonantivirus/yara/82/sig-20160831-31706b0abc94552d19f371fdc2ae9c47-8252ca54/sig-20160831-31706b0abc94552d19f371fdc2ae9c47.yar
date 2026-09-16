rule sig_20160831_31706b0abc94552d19f371fdc2ae9c47 {
  meta:
    description = "datamaliciousorder - file 20160831_31706b0abc94552d19f371fdc2ae9c47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa3a34b0bafdb2421438200d9d840dedfc821f24110697dd6e93019bb98bc9e7"

  strings:
    $s1  = "aver!!!!!!BDx7shut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s3  = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfuckin" ascii
    $s6  = "t-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s7  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfucking" ascii
    $s8  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s9  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s10 = "aver!!!!!!KVj7shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfuck" ascii
    $s11 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfuck" ascii
    $s14 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuc" ascii
    $s18 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfuckin" ascii
    $s19 = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuck" ascii
    $s20 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}