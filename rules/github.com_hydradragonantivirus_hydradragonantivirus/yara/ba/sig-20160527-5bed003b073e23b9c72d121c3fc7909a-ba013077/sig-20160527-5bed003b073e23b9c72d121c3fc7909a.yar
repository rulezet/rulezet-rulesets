rule sig_20160527_5bed003b073e23b9c72d121c3fc7909a {
  meta:
    description = "datamaliciousorder - file 20160527_5bed003b073e23b9c72d121c3fc7909a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "185c6b1291d4f506061737e5340d3f78464212be118532c576ec6c056f77b795"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<av8qbgjBh.length;i++)if(i%2==0)x.push(av8qbgjBh[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}