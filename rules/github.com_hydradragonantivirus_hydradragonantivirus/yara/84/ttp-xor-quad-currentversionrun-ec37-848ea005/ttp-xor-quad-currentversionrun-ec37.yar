rule TTP_XOR_QUAD_CurrentVersionRun_ec37 {
  strings:
    $key_ec37 = { bf 58 [2] 9b 56 [2] b0 7a [2] 9e 58 [2] 8a 43 [2] 85 59 [2] 9b 44 [2] 99 45 [2] 82 43 [2] 9e 44 [2] 82 6b }

  condition:
    any of them
}