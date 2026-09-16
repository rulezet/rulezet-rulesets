rule sig_20160527_142c1ab7f1f7a446e172f4a70a9dad84 {
  meta:
    description = "datamaliciousorder - file 20160527_142c1ab7f1f7a446e172f4a70a9dad84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d44daf53a2115d9f5099494d2dba7d2f8ae88c32a1db348cb574077b3d5ee952"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ac1NpKOg5.length;i++)if(i%2==0)x.push(ac1NpKOg5[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}