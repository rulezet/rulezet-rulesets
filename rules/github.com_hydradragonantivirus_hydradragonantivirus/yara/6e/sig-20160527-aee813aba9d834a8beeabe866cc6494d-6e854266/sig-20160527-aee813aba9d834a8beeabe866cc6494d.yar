rule sig_20160527_aee813aba9d834a8beeabe866cc6494d {
  meta:
    description = "datamaliciousorder - file 20160527_aee813aba9d834a8beeabe866cc6494d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a653bb4f712fceabc72608855d94982c2a4526601effa22ed9f06b1d84d0520c"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a9KDFek8Hwo.length;i++)if(i%2==0)x.push(a9KDFek8Hwo[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}