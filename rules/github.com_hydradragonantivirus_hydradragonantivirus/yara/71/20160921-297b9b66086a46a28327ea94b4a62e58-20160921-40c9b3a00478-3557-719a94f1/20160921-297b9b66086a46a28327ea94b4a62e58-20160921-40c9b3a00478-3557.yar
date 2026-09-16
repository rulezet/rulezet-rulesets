rule _20160921_297b9b66086a46a28327ea94b4a62e58_20160921_40c9b3a00478_3557 {
  meta:
    description = "datamaliciousorder - from files 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash2       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash3       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"

  strings:
    $s1 = "n \"PTs\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(fun" ascii
    $s2 = "000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TR" ascii
    $s3 = "eturn \"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})()," ascii
    $s4 = "\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s5 = "n\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Mt\";})(),(function " ascii
    $s6 = ",(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}