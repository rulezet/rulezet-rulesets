rule sig_20160525_5ee95a1cf0c645f66c4e81f1130bf67d {
  meta:
    description = "datamaliciousorder - file 20160525_5ee95a1cf0c645f66c4e81f1130bf67d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79a6807f4e6447100c0a8e28b0d63e22e3a5751092181960358e48bdfa690d78"

  strings:
    $s1 = "6x\\\\el\" = eixodu rav\\n;\"h47x\\\\\" = gsmu rav\\n;\"ec6x\\\\\" = suidarelcitrapu rav\\n;\"86x\\\\tgn\" = dnenoisillocu rav'[" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}