rule _20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7_20160921_a3beeaf53744_4795 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash2       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"

  strings:
    $s1 = "turn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})()," ascii
    $s2 = " \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s3 = "eturn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s4 = "n f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s5 = "rn \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}