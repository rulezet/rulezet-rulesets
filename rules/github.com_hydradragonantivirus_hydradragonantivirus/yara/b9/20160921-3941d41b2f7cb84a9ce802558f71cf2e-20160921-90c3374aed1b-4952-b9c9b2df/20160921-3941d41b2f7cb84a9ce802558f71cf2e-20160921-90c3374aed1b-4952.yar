rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_90c3374aed1b_4952 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_90c3374aed1b4618a92eb40cb007c4b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"

  strings:
    $s1 = "eturn \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Rh\";})(),(" ascii
    $s2 = "ction f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){retu" ascii
    $s3 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Y" ascii
    $s4 = "(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";}" ascii
    $s5 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}