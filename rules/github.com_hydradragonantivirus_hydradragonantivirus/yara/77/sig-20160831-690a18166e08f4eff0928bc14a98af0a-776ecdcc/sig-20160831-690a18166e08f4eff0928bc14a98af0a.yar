rule sig_20160831_690a18166e08f4eff0928bc14a98af0a {
  meta:
    description = "datamaliciousorder - file 20160831_690a18166e08f4eff0928bc14a98af0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "507622e358b186b69c0f843c62b35afaf10669537b1f7a901178c6f5ae9f7dc3"

  strings:
    $s1  = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!APzshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfu" ascii
    $s4  = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfuckin" ascii
    $s6  = "aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfu" ascii
    $s10 = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfuckin" ascii
    $s11 = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Gcshut-the-fuck-up-motherfuckin" ascii
    $s12 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucki" ascii
    $s14 = "t-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s15 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!XGx6shut-the-fuck-up-motherfucking-aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfuc" ascii
    $s18 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}