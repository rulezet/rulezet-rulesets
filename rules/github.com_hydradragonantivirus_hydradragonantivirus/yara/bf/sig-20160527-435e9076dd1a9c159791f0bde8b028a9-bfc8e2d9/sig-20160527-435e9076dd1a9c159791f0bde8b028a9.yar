rule sig_20160527_435e9076dd1a9c159791f0bde8b028a9 {
  meta:
    description = "datamaliciousorder - file 20160527_435e9076dd1a9c159791f0bde8b028a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a81e16b2ac55b112c4c5f1abadf5b221ac55a69c3616d11d5e539f503ef3e3f"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aVNyPJ.length;i++)if(i%2==0)x.push(aVNyPJ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}