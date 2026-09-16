rule _20160921_b15ce64784b080eff109e1bd1b00ebf6_20160921_f3a36d70a836_5640 {
  meta:
    description = "datamaliciousorder - from files 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = "Sq\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s2 = "),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Iq\";})(),(function f000()" ascii
    $s3 = " \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(fu" ascii
    $s4 = "(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){" ascii
    $s5 = "000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}