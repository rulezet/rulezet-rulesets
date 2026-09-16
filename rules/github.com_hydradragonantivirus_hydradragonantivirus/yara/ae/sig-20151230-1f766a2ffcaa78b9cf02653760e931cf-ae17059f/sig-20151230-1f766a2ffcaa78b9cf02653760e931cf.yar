rule sig_20151230_1f766a2ffcaa78b9cf02653760e931cf {
  meta:
    description = "datamaliciousorder - file 20151230_1f766a2ffcaa78b9cf02653760e931cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfcc4ee531a81955d4e6182c47a529098961dc5122907fcbcedf2f820e94aeac"

  strings:
    $s1 = "print (anevekglax);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}