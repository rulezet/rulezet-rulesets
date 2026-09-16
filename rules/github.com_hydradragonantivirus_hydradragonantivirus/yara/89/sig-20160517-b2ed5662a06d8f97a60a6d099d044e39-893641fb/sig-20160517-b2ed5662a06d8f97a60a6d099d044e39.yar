rule sig_20160517_b2ed5662a06d8f97a60a6d099d044e39 {
  meta:
    description = "datamaliciousorder - file 20160517_b2ed5662a06d8f97a60a6d099d044e39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a4843fedc4b2808c4a1881580b700115d36cf03a89001624e8e26db27fba6e1"

  strings:
    $s1 = "var ft3='vxhielaa4b1vrkxsjv ebm41zepsbftratl4eark3zkyz4b1sucxqqix3wgbwelvprrzuvygdao2kqsskqaq=p4xot\\'ciwkttahey1cf4vv2njvqdfime" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}