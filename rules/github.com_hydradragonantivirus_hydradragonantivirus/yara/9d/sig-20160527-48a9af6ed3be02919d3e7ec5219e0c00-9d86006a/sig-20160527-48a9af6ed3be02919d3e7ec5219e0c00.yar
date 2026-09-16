rule sig_20160527_48a9af6ed3be02919d3e7ec5219e0c00 {
  meta:
    description = "datamaliciousorder - file 20160527_48a9af6ed3be02919d3e7ec5219e0c00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3055f7370d94f37ab93da7994f91ff400c4021f1239759a19afebb4e58b49b88"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aEVnn2.length;i++)if(i%2==0)x.push(aEVnn2[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}