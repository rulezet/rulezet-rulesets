rule sig_20160527_21c38a8eb0554933f62f720f77fac352 {
  meta:
    description = "datamaliciousorder - file 20160527_21c38a8eb0554933f62f720f77fac352.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7434fc1902a2dbdd573be759e2dc18eb8f7a263404e38592bdbfd73af9ae67e"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<acIo6mvj6.length;i++)if(i%2==0)x.push(acIo6mvj6[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}