rule sig_20160527_529cee3fead1f9ab5d40e3b678cf1645 {
  meta:
    description = "datamaliciousorder - file 20160527_529cee3fead1f9ab5d40e3b678cf1645.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b781b016aa8726cfdccfcbb6f03f9423c6fdb20f0ed757ebf4b132aebd8d33a"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a4KvApON.length;i++)if(i%2==0)x.push(a4KvApON[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}