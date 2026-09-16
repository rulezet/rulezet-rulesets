rule sig_20160530_598f957adf6b46564584bb7a77af457a {
  meta:
    description = "datamaliciousorder - file 20160530_598f957adf6b46564584bb7a77af457a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61e8c56559028972637694042506b85156b1bc338f8159a2929a31e228de49c1"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aw541cF.length;i++)if(i%2==0)x.push(aw541cF[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}