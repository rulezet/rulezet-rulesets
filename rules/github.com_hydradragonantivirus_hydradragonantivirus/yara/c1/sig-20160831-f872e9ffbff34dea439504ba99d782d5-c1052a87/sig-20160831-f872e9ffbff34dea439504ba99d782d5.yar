rule sig_20160831_f872e9ffbff34dea439504ba99d782d5 {
  meta:
    description = "datamaliciousorder - file 20160831_f872e9ffbff34dea439504ba99d782d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ffc016a9b5dee9b6ed4a2884e6139ee82a42c445c4cdbe412e018108b97565b"

  strings:
    $s1  = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfuckin" ascii
    $s6  = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuckin" ascii
    $s7  = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfucking" ascii
    $s8  = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s9  = "aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s11 = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s15 = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s18 = "aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfuc" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}