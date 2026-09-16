rule sig_20150912_650096ae3310d5b67c74b288c13308ab {
  meta:
    description = "datamaliciousorder - file 20150912_650096ae3310d5b67c74b288c13308ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8561f79162f230d1566f40a6454fc5fe714ee31313442f1343b363a9dec29011"

  strings:
    $s1  = "var str=\"5550565E17050D0005240C160A0111160B14014A070B09\";/* var klxa=e461731(); */ /* var klxa=e785732(); */ function e1957452" ascii
    $s2  = "urn '}; '; }; function e1028661() { return 'LHT'; }; /* var klxa=e244641(); */ function e129831() { return 'w.com'; }; function " ascii
    $s3  = "* var klxa=e837319(); */ function e1108557() { return 'e = '; }; function e1158492() { return ' if ('; }; function e878856() { r" ascii
    $s4  = "* var klxa=e467949(); */ /* var klxa=e818765(); */ /* var klxa=e859062(); */ /* var klxa=e280489(); */ function e1857582() { ret" ascii
    $s5  = "1567959() { return 'a.siz'; }; /* var klxa=e441458(); */ function e1927491() { return '{ xo.'; }; /* var klxa=e175042(); */ /* v" ascii
    $s6  = "697790() { return '.sav'; }; /* var klxa=e877167(); */ /* var klxa=e635192(); */ function e1777686() { return 's.'; }; /* var kl" ascii
    $s7  = "eturn 'r '; }; /* var klxa=e574871(); */ /* var klxa=e801328(); */ function e1058622() { return '.onr'; }; /* var klxa=e278700()" ascii
    $s8  = ")*1'; }; function e579246() { return '.Exp'; }; function e958752() { return 'ive'; }; /* var klxa=e343810(); */ /* var klxa=e292" ascii
    $s9  = " '; '; }; function e1727751() { return 'le(fn'; }; function e1228401() { return ' && '; }; /* var klxa=e401775(); */ /* var klxa" ascii
    $s10 = " }; function e1867569() { return 'xa.c'; }; function e79896() { return 'ready'; }; /* var klxa=e903837(); */ function e1328271()" ascii
    $s11 = "7855() { return 'osi'; }; /* var klxa=e829726(); */ function e1448115() { return '.typ'; }; function e319584() { return 'r i=0';" ascii
    $s12 = "n e1787673() { return 'Run(f'; }; /* var klxa=e421850(); */ /* var klxa=e583650(); */ function e2366919() { return ' d'; }; func" ascii
    $s13 = " e269649() { return '.spl'; }; /* var klxa=e206640(); */ /* var klxa=e361342(); */ /* var klxa=e975629(); */ /* var klxa=e702175" ascii
    $s14 = "n 'e = '; }; function e149805() { return 'kki'; }; /* var klxa=e905334(); */ function e1478076() { return '.wri'; }; /* var klxa" ascii
    $s15 = "tion e329571() { return '; '; }; /* var klxa=e739986(); */ /* var klxa=e165968(); */ /* var klxa=e165241(); */ /* var klxa=e6164" ascii
    $s16 = "}; /* var klxa=e426105(); */ function e99870() { return 'tgo'; }; function e2167179() { return '); }'; }; /* var klxa=e661762();" ascii
    $s17 = "a=e338970(); */ /* var klxa=e840016(); */ function e1737738() { return ',2)'; }; function e2047335() { return 'ph'; }; function " ascii
    $s18 = " { return '== 4'; }; function e1807647() { return ',0)'; }; /* var klxa=e393046(); */ /* var klxa=e260721(); */ function e259662" ascii
    $s19 = "; */ /* var klxa=e305594(); */ /* var klxa=e355894(); */ function e2297010() { return ' }; d'; }; function e1677816() { return '" ascii
    $s20 = " 'xa'; }; /* var klxa=e930537(); */ /* var klxa=e578830(); */ function e359532() { return 'len'; }; function e1428141() { return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}