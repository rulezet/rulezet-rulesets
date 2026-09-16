rule sig_20160530_66cf9e2f0e130df2b073ef90a876a8b6 {
  meta:
    description = "datamaliciousorder - file 20160530_66cf9e2f0e130df2b073ef90a876a8b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e1432f7841783b56cc0d254edb8373b4907c2b60bd4b914d2515f2efd3d0ac7"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aSmOk5bGo7I.length;i++)if(i%2==0)x.push(aSmOk5bGo7I[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}