rule sig_20160517_a2864b6bb4f5d63d0650b2134455b291 {
  meta:
    description = "datamaliciousorder - file 20160517_a2864b6bb4f5d63d0650b2134455b291.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e189c7c2e546561614326bb43ec95a261d800b6dbd12660c37a8be5bd13955"

  strings:
    $s1 = "var uoxz2='vmpavlavtvycrp3tsn wpbf3ghlpr4jbjjzu1zvkcqxsqkuouhqqkibe43ji1bfyu1qh4jk4vqmysscasian=sverf\\'wzjtjtuytutczvwdgnqlwxei" ascii
    $s2 = "S\"+\"cript\"+\".RegE\"+\"xp\");   bytbnd2m4=r4+\"v\"+\"al\";   WScript.lister=5;   bytbnd2m4=\"\"+\"s\";   ww=232323;   }catch(" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}