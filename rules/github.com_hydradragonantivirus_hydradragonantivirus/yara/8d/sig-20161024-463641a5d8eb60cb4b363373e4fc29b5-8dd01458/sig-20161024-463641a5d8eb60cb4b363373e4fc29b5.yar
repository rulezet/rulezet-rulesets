rule sig_20161024_463641a5d8eb60cb4b363373e4fc29b5 {
  meta:
    description = "datamaliciousorder - file 20161024_463641a5d8eb60cb4b363373e4fc29b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3539444e1c92da3a8edde020f551fb054104343db47beba0e7eddf26fdaa38"

  strings:
    $s1 = "} while (rc++ < zg);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}