rule sig_20160527_8da3cabe5c579fcf27b754dccbfedb1c {
  meta:
    description = "datamaliciousorder - file 20160527_8da3cabe5c579fcf27b754dccbfedb1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7decedee5f3d8a5e9d1524c5f83071875531c8aac10952f584900bdaf6e600dc"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aZ8W4K2zYW.length;i++)if(i%2==0)x.push(aZ8W4K2zYW[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}