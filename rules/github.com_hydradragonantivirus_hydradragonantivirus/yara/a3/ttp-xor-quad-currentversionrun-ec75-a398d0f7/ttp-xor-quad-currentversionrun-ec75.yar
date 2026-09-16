rule TTP_XOR_QUAD_CurrentVersionRun_ec75 {
  strings:
    $key_ec75 = { bf 1a [2] 9b 14 [2] b0 38 [2] 9e 1a [2] 8a 01 [2] 85 1b [2] 9b 06 [2] 99 07 [2] 82 01 [2] 9e 06 [2] 82 29 }

  condition:
    any of them
}