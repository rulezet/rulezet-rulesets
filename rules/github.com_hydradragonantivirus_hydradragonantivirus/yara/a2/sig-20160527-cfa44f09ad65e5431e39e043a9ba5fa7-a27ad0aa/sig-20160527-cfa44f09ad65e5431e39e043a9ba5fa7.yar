rule sig_20160527_cfa44f09ad65e5431e39e043a9ba5fa7 {
  meta:
    description = "datamaliciousorder - file 20160527_cfa44f09ad65e5431e39e043a9ba5fa7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc02e8bd0f8a6310941bf84f84e3c1c65a59d5b8c6719fe1a376e667cc32189e"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<atUCNynz3TK.length;i++)if(i%2==0)x.push(atUCNynz3TK[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}