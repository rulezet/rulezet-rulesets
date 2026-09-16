rule sig_20160527_d808c6d0ae2dcfcc30197e29b0735854 {
  meta:
    description = "datamaliciousorder - file 20160527_d808c6d0ae2dcfcc30197e29b0735854.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d74a0757c6942c4b62bf61a9eff633ff63390780d0fc7bb11ae21602185abb86"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<atcijaaC4uC.length;i++)if(i%2==0)x.push(atcijaaC4uC[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}