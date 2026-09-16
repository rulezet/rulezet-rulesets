rule sig_20161024_17a488c56552213b748d31ef255f3da9 {
  meta:
    description = "datamaliciousorder - file 20161024_17a488c56552213b748d31ef255f3da9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b745828bb32ca723c958d1379511f931383bfff80c7637e313127fad03c80b4"

  strings:
    $s1 = "} while (vd++ < dn);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}