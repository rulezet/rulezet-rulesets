rule TTP_XOR_QUAD_CurrentVersionRun_ec03 {
  strings:
    $key_ec03 = { bf 6c [2] 9b 62 [2] b0 4e [2] 9e 6c [2] 8a 77 [2] 85 6d [2] 9b 70 [2] 99 71 [2] 82 77 [2] 9e 70 [2] 82 5f }

  condition:
    any of them
}