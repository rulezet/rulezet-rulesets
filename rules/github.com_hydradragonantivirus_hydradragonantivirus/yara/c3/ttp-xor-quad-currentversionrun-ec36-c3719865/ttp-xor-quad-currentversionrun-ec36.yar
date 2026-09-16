rule TTP_XOR_QUAD_CurrentVersionRun_ec36 {
  strings:
    $key_ec36 = { bf 59 [2] 9b 57 [2] b0 7b [2] 9e 59 [2] 8a 42 [2] 85 58 [2] 9b 45 [2] 99 44 [2] 82 42 [2] 9e 45 [2] 82 6a }

  condition:
    any of them
}