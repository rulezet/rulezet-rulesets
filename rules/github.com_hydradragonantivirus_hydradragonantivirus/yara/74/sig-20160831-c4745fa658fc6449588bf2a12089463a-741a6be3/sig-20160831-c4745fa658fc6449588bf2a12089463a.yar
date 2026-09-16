rule sig_20160831_c4745fa658fc6449588bf2a12089463a {
  meta:
    description = "datamaliciousorder - file 20160831_c4745fa658fc6449588bf2a12089463a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f95452e9970cd969f0d34d777fcc8eb30d5d4c5dbb1b9c584c8ae98117a83c9"

  strings:
    $s1  = "aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfuck" ascii
    $s2  = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s3  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfu" ascii
    $s4  = "-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s5  = "t-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s6  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfuc" ascii
    $s7  = "he-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s8  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfu" ascii
    $s9  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuc" ascii
    $s12 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfuckin" ascii
    $s14 = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s15 = "the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s16 = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s18 = "aver!!!!!!Bishut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ib3shut-the-fuck-up-motherfuckin" ascii
    $s19 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}