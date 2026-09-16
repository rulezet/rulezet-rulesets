rule sig_20160831_50c7c7f14b752c24f709b61cb7fc3b0c {
  meta:
    description = "datamaliciousorder - file 20160831_50c7c7f14b752c24f709b61cb7fc3b0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5d9e7b00be5451b25875db9efa47e8612092fdd53b8fd99aebf612cc7d9b696"

  strings:
    $s1  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfu" ascii
    $s2  = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qsshut-the-fuck-up-motherfucki" ascii
    $s3  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ya2shut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfuc" ascii
    $s5  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuck" ascii
    $s7  = "aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!LAo4shut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfuckin" ascii
    $s10 = "aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfuck" ascii
    $s11 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!ZVyshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s16 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucki" ascii
    $s17 = "-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s18 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfuckin" ascii
    $s19 = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Qf2shut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}