rule _Virus_Autorun_Gen_Variant_Application_Barys_1471_Virus_Autorun__303 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Variant.Application.Barys.1471.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.tyZ@aSgChKg_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36bbc80169bd128d160fb3869dcf23891b69a7765d8abb171897c9dfd0d58e3a"
    hash2       = "0ea76f5343284061fe91a1363d0a2116b76db249e7de5cc17a6971f30f805011"
    hash3       = "c25118c87134ffa298b9ec21b6abbfb10ced5f41dee519e34b593db27e0ce502"
    hash4       = "ed76141284fb07fe8c33040d0b95b54c78bbf494dfac4c802d2913d2c549d8f8"

  strings:
    $s1  = "Failed to create target file(%s), code=%u" fullword wide
    $s2  = "!!! Download termination was requested !!!" fullword wide
    $s3  = "File download requested '%s'" fullword wide
    $s4  = "Ftp set directory failed '%s', code=%u" fullword wide
    $s5  = "Writing target file %u bytes" fullword wide
    $s6  = "File #%u downloaded, size=%u, crc32=x%08X" fullword wide
    $s7  = "Parsing command" fullword ascii
    $s8  = "*** TOO MANY ARGUMENTS ***" fullword ascii
    $s9  = "Standard shell splitter" fullword ascii
    $s10 = "Open internet with agent name '%s'" fullword wide
    $s11 = "Ftp open file failed" fullword wide
    $s12 = "Create %s event failed, code=%u" fullword wide
    $s13 = "Warning: Query internet %s timeout failed, code=%u" fullword wide
    $s14 = "Only http addresses are supported!" fullword wide
    $s15 = "DownloadFile. Invalid arguments" fullword wide
    $s16 = "Authorization failed, code=%u" fullword wide
    $s17 = "Connection failed, code=%u" fullword wide
    $s18 = "Failed to open source file(%s), code=%u" fullword wide
    $s19 = "Download finished, %u bytes retrieved" fullword wide
    $s20 = "WriteFile(%s) failed, no data, code=%u" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}