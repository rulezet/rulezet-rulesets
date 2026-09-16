rule _20160921_2c5e8ccbd48636e7c625aae6ef954560_20160921_eb8df0d94f3c_4819 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash2       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1 = "{return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})" ascii
    $s2 = "uck(){return \"CCb\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Jo\"" ascii
    $s3 = "return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(" ascii
    $s4 = "urn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(" ascii
    $s5 = "ction fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}