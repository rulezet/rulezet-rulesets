rule sig_20160527_1d9897c65a94f3bb7431c68ac0f372a8 {
  meta:
    description = "datamaliciousorder - file 20160527_1d9897c65a94f3bb7431c68ac0f372a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a95c2106bb2772661f82407cda915cd8a6db2e5c3378d847227547385c4eed05"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aNU7eaoW.length;i++)if(i%2==0)x.push(aNU7eaoW[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}