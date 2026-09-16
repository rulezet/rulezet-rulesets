rule sig_20160527_7159c193b4cf92d038401a84aed230bd {
  meta:
    description = "datamaliciousorder - file 20160527_7159c193b4cf92d038401a84aed230bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73b01d4d826808371c803c1bb204dc2cdbc2d0afce3c9b11d04a121a4882bbe5"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<anudXj.length;i++)if(i%2==0)x.push(anudXj[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}