rule _20160921_202394e6610dfa0f27f737c781d5c579_20160921_ded524cdc972_3495 {
  meta:
    description = "datamaliciousorder - from files 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash2       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000()" ascii
    $s2 = "unction f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){retu" ascii
    $s3 = "rn \"EZu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(f" ascii
    $s4 = "turn \"Yz\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s5 = ";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f00" ascii
    $s6 = "f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Oe\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}