rule _20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5_20160921_ec2541ade561_5277 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash2       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1 = "n f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Z" ascii
    $s2 = "000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi" ascii
    $s3 = "tion f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return" ascii
    $s4 = "on f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s5 = ";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}