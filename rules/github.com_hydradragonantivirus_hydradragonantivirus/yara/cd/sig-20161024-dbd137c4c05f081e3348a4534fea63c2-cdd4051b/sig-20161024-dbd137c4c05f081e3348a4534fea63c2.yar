rule sig_20161024_dbd137c4c05f081e3348a4534fea63c2 {
  meta:
    description = "datamaliciousorder - file 20161024_dbd137c4c05f081e3348a4534fea63c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b53fcbe5c62b7c5ac507f734b5d90c5d5d39dfbb640df1f866acc30bf736c47e"

  strings:
    $s1 = "} while (qf++ < om);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}