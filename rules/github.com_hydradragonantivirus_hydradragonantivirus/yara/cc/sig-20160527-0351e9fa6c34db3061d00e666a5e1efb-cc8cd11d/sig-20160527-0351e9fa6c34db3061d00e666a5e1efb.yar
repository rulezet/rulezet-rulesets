rule sig_20160527_0351e9fa6c34db3061d00e666a5e1efb {
  meta:
    description = "datamaliciousorder - file 20160527_0351e9fa6c34db3061d00e666a5e1efb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65655b8215c23db8ce2a58dcc6b7f7a8ae266a2a58028102f1e600ff549639d6"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a1T3YWGyRj.length;i++)if(i%2==0)x.push(a1T3YWGyRj[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}