rule TTP_XOR_QUAD_CurrentVersionRun_ec23 {
  strings:
    $key_ec23 = { bf 4c [2] 9b 42 [2] b0 6e [2] 9e 4c [2] 8a 57 [2] 85 4d [2] 9b 50 [2] 99 51 [2] 82 57 [2] 9e 50 [2] 82 7f }

  condition:
    any of them
}