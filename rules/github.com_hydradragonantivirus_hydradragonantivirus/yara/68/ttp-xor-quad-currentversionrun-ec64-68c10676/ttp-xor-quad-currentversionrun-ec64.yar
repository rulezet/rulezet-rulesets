rule TTP_XOR_QUAD_CurrentVersionRun_ec64 {
  strings:
    $key_ec64 = { bf 0b [2] 9b 05 [2] b0 29 [2] 9e 0b [2] 8a 10 [2] 85 0a [2] 9b 17 [2] 99 16 [2] 82 10 [2] 9e 17 [2] 82 38 }

  condition:
    any of them
}