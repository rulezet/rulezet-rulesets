rule sig_20160516_e89ca3148449ecdcd3226ddef229e3ce {
  meta:
    description = "datamaliciousorder - file 20160516_e89ca3148449ecdcd3226ddef229e3ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce5be21b58192c2a34bebbb33f365e618a69ec574f74742c13df221af004add9"

  strings:
    $s1 = "var gnbh='vhcbakas1ukkrvjbyp wdplqeleapswkiwfvfno2osbhwtfggm2uj1ayed4thvz33pixl2rukeaiysuajpyt=wcvuq\\'tez4hta2hvacmqp3iniymxxid" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}