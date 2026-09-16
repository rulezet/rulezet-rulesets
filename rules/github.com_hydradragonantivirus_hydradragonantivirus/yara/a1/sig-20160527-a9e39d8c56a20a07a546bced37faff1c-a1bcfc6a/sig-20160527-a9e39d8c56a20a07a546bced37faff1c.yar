rule sig_20160527_a9e39d8c56a20a07a546bced37faff1c {
  meta:
    description = "datamaliciousorder - file 20160527_a9e39d8c56a20a07a546bced37faff1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdc68692074e032733dd2b1868d6b50deff5f29ac0486e1e6192ccd8d0e3d057"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aIwItDYS.length;i++)if(i%2==0)x.push(aIwItDYS[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}