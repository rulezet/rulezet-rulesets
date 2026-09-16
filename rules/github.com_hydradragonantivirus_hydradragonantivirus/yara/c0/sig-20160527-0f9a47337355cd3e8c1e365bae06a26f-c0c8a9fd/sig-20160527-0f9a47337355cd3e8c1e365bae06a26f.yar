rule sig_20160527_0f9a47337355cd3e8c1e365bae06a26f {
  meta:
    description = "datamaliciousorder - file 20160527_0f9a47337355cd3e8c1e365bae06a26f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "811d1013af8835675f6c514f6c7e23f5a01bfe693a9363b74779d61cdb5496a8"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aglh3NRSXs.length;i++)if(i%2==0)x.push(aglh3NRSXs[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}