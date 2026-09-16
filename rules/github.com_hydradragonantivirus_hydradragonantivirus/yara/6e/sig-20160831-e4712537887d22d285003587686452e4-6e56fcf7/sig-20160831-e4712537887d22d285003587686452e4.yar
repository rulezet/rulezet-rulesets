rule sig_20160831_e4712537887d22d285003587686452e4 {
  meta:
    description = "datamaliciousorder - file 20160831_e4712537887d22d285003587686452e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94e01d3d3e32b20d2f650016bddc61c1dfcbcab4cdef28689b9168f92045a330"

  strings:
    $s1  = "aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfuc" ascii
    $s2  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuc" ascii
    $s3  = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!KVj7shut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfuc" ascii
    $s5  = "aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!GNp9shut-the-fuck-up-motherfucking-aver!!!!!!Qf2shut-the-fuck-up-motherfucking-aver!!!!!!BDx7shut-the-fuck-up-motherfu" ascii
    $s7  = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!Ug6shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!ZVyshut-the-fuck-up-motherfucking-aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucki" ascii
    $s10 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s11 = "he-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s12 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!Ncshut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfuckin" ascii
    $s14 = "aver!!!!!!Ncshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucking" ascii
    $s15 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfuck" ascii
    $s16 = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s18 = "e-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s19 = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}