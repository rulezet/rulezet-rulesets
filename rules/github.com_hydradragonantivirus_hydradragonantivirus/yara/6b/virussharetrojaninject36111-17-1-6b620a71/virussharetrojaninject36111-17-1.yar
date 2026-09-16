rule VirusShareTrojanInject36111_17_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject36111_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "552d8d01f02ee396385097544499d26612e11a4cd0381a58c45436ec614ec02b"

  strings:
    $s1 = "cise`Uf8j=?tonob75go;kcis" fullword ascii
    $s2 = "]lasA." fullword ascii
    $s3 = "ktr*DesK" fullword ascii
    $s4 = "qeKBktr*DesK9pi\\rc" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}