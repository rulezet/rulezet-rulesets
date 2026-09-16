rule _20160831_638fe6816112d7dfe0260ba8a65f1bff_20160831_8ca14f9a2355_94 {
  meta:
    description = "datamaliciousorder - from files 20160831_638fe6816112d7dfe0260ba8a65f1bff.js, 20160831_8ca14f9a2355c124cbae709c8501baa4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65bee54058e80557fe9e68fbc62482c2a663d950423d1e7e4feb106e3f59ce58"
    hash2       = "ec11617994a5c5f9ca4606c7f39c3556cc69f9b51c8c50313c97e338b5d1bbd4"

  strings:
    $s1 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfucki" ascii
    $s2 = "aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfu" ascii
    $s3 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucki" ascii
    $s4 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucki" ascii
    $s5 = "aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!Dy2shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}