rule TTP_XOR_QUAD_CurrentVersionRun_ec13 {
  strings:
    $key_ec13 = { bf 7c [2] 9b 72 [2] b0 5e [2] 9e 7c [2] 8a 67 [2] 85 7d [2] 9b 60 [2] 99 61 [2] 82 67 [2] 9e 60 [2] 82 4f }

  condition:
    any of them
}