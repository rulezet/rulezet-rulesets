rule sig_20160523_38c50f32a8606ff0f3ad1c0147909dcb {
  meta:
    description = "datamaliciousorder - file 20160523_38c50f32a8606ff0f3ad1c0147909dcb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "073584b69bdaa255391e4eea68a10b4b005ec01ca1d7a36d1d682fe9f468e154"

  strings:
    $s1 = "reverse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}