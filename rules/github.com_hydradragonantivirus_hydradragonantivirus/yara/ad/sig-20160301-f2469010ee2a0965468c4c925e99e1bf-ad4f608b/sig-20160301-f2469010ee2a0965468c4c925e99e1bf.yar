rule sig_20160301_f2469010ee2a0965468c4c925e99e1bf {
  meta:
    description = "datamaliciousorder - file 20160301_f2469010ee2a0965468c4c925e99e1bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24e161f47dec27235096a340b2420285e931b080e388855a6211a8a33722b3cf"

  strings:
    $s1 = "partnerPostscript = ((0 ^ 1), this);" fullword ascii
    $s2 = " \"\\u0076ol\\u0063\" + \"an\\u006f\", function String.prototype.energySelection() {" fullword ascii
    $s3 = "while(factSpecification[(\"\\u0073ho\\u0063\\u006b\", \"ph\\u0065\\u006e\\u006f\" + \"\\u006de\\u006e\" + \"\\u006fn\", \"\\u006" ascii
    $s4 = "factSpecification[(\"\\u0061ss\" + \"em\\u0062\\u006c\" + \"\\u0079\", \"\\u0065xp\" + \"e\" + \"ri\\u006den\" + \"\\u0074\", \"" ascii
    $s5 = "while(factSpecification[(\"\\u0073ho\\u0063\\u006b\", \"ph\\u0065\\u006e\\u006f\" + \"\\u006de\\u006e\" + \"\\u006fn\", \"\\u006" ascii
    $s6 = "} catch(masterExamine) {};" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    all of them
}