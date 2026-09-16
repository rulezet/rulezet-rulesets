rule _20160831_659cccb68fc45da7ec5cd6cd8da02e5c_20160831_b151b9ea4061_73 {
  meta:
    description = "datamaliciousorder - from files 20160831_659cccb68fc45da7ec5cd6cd8da02e5c.js, 20160831_b151b9ea4061229c67f340edfd370ca6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cdd65caa06f9fcf3ca28945410b66123b06a5d8a28fb6c5a98c5e7ee58d2e84"
    hash2       = "26e92ab7936c62ce714ee0d4d6fffb039dd9b74478dcb36bc84c73852fbe3c8f"

  strings:
    $s1 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfu" ascii
    $s2 = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucki" ascii
    $s3 = "aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfuc" ascii
    $s4 = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s5 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucki" ascii
    $s6 = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfucki" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}