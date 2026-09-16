rule sig_20161024_c4855e4940e09c3c3a627d7ff297b303 {
  meta:
    description = "datamaliciousorder - file 20161024_c4855e4940e09c3c3a627d7ff297b303.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d72f98b1334b6888436dd6f41114e82b7f00e5f1755e8b95fb0fb2af3419f5c2"

  strings:
    $s1 = "} while (cm++ < lf0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}