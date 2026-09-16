rule TTP_XOR_QUAD_CurrentVersionRun_ec46 {
  strings:
    $key_ec46 = { bf 29 [2] 9b 27 [2] b0 0b [2] 9e 29 [2] 8a 32 [2] 85 28 [2] 9b 35 [2] 99 34 [2] 82 32 [2] 9e 35 [2] 82 1a }

  condition:
    any of them
}