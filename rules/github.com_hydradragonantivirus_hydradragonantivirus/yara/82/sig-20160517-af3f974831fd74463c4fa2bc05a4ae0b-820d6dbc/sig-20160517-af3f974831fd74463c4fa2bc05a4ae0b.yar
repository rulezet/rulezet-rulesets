rule sig_20160517_af3f974831fd74463c4fa2bc05a4ae0b {
  meta:
    description = "datamaliciousorder - file 20160517_af3f974831fd74463c4fa2bc05a4ae0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a070889f20361b3af437b241cd42ce42fb1790be964fee23a0c873a565d8698e"

  strings:
    $s1 = "var uoxz2='vmpavlavtvycrp3tsn wpbf3ghlpr4jbjjzu1zvkcqxsqkuouhqqkibe43ji1bfyu1qh4jk4vqmysscasian=sverf\\'wzjtjtuytutczvwdgnqlwxei" ascii
    $s2 = "S\"+\"cript\"+\".RegE\"+\"xp\");   bytbnd2m4=r4+\"v\"+\"al\";   WScript.lister=5;   bytbnd2m4=\"\"+\"s\";   ww=232323;   }catch(" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}