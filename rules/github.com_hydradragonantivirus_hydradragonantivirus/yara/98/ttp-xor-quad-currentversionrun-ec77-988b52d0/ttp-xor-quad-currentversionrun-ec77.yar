rule TTP_XOR_QUAD_CurrentVersionRun_ec77 {
  strings:
    $key_ec77 = { bf 18 [2] 9b 16 [2] b0 3a [2] 9e 18 [2] 8a 03 [2] 85 19 [2] 9b 04 [2] 99 05 [2] 82 03 [2] 9e 04 [2] 82 2b }

  condition:
    any of them
}