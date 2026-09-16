rule sig_20160527_46d12b6120f3165af5f00e296bbffca7 {
  meta:
    description = "datamaliciousorder - file 20160527_46d12b6120f3165af5f00e296bbffca7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43bbf1244820a60bae6f8faf4edef5e568fc15e1ef8661cbfd8dee55f66b7b05"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a4B2fT.length;i++)if(i%2==0)x.push(a4B2fT[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}