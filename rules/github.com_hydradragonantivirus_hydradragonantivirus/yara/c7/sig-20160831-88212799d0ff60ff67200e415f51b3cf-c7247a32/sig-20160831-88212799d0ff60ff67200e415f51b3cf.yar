rule sig_20160831_88212799d0ff60ff67200e415f51b3cf {
  meta:
    description = "datamaliciousorder - file 20160831_88212799d0ff60ff67200e415f51b3cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0e0df0181c6d7f051356151bbeb0731e8823ab6af55196d63859dc13141d599"

  strings:
    $s1  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfucki" ascii
    $s3  = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfuckin" ascii
    $s5  = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!MQlshut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking" ascii
    $s10 = "aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuckin" ascii
    $s11 = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfuc" ascii
    $s12 = "aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuckin" ascii
    $s13 = "the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s14 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuckin" ascii
    $s15 = "aver!!!!!!BZbshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!APzshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}