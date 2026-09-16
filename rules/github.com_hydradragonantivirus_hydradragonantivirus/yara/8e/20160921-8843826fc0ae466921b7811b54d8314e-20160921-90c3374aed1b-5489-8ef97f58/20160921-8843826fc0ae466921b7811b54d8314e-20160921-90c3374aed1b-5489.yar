rule _20160921_8843826fc0ae466921b7811b54d8314e_20160921_90c3374aed1b_5489 {
  meta:
    description = "datamaliciousorder - from files 20160921_8843826fc0ae466921b7811b54d8314e.js, 20160921_90c3374aed1b4618a92eb40cb007c4b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"
    hash2       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"

  strings:
    $s1 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(" ascii
    $s2 = "(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DIa\";" ascii
    $s3 = "eturn \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s4 = "ction f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii
    $s5 = "XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}