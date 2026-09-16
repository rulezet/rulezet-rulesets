rule sig_20160527_4141d811b355de023e7d49a5f7b8a46d {
  meta:
    description = "datamaliciousorder - file 20160527_4141d811b355de023e7d49a5f7b8a46d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97fd7136d608c1c80049319264ad254724eb98006adc106ae308f76a48744262"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aEQnuhuE.length;i++)if(i%2==0)x.push(aEQnuhuE[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}