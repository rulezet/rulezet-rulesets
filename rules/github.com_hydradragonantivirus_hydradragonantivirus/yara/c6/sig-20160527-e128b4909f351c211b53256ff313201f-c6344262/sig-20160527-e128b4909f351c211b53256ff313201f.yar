rule sig_20160527_e128b4909f351c211b53256ff313201f {
  meta:
    description = "datamaliciousorder - file 20160527_e128b4909f351c211b53256ff313201f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d7b8ecde710263e6a00539f405f701807bf5b1a1326b9fad37ae8ab6cc55a28"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<akRDpxbt.length;i++)if(i%2==0)x.push(akRDpxbt[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}