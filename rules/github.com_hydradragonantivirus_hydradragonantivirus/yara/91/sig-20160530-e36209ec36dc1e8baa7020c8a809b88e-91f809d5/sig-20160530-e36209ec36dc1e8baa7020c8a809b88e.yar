rule sig_20160530_e36209ec36dc1e8baa7020c8a809b88e {
  meta:
    description = "datamaliciousorder - file 20160530_e36209ec36dc1e8baa7020c8a809b88e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bc5d1b10d657b4907cd815d29b964c8bfd4820f8f4344eee6eb201a9fc7b29e"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a2f6m8f.length;i++)if(i%2==0)x.push(a2f6m8f[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}