rule sig_20151207_ba5a681820e2419b2a070937208ca566 {
  meta:
    description = "datamaliciousorder - file 20151207_ba5a681820e2419b2a070937208ca566.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01d185968d60b839845de8288ea3368b63a6f4bf983e2c9b8079378c4c7be6de"

  strings:
    $s1 = "var str=\"5553565E0E0501070F0108240901100508090D0A00174A070B095E275E17050205160D0A05090D060D054A01175E17555E5550505D505053545D54" ascii
    $s2 = "function j9(){return c1;};var y3='ntSt';var m0='dEnvi';var u4='b ';var v5='= W';var d7='esp';var i7='; va';o1=p9;b3+=o1;o1=u4;b3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}