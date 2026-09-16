rule sig_20161024_e5269fa92afb22051f761ef02578cd70 {
  meta:
    description = "datamaliciousorder - file 20161024_e5269fa92afb22051f761ef02578cd70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45c8f41643b22d92cbc60d993bd029a0af65efeeb25f9d94195a54e2fba5185"

  strings:
    $s1 = "} while (xw++ < mc0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}