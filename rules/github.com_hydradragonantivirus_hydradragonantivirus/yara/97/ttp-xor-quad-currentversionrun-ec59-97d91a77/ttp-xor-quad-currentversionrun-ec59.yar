rule TTP_XOR_QUAD_CurrentVersionRun_ec59 {
  strings:
    $key_ec59 = { bf 36 [2] 9b 38 [2] b0 14 [2] 9e 36 [2] 8a 2d [2] 85 37 [2] 9b 2a [2] 99 2b [2] 82 2d [2] 9e 2a [2] 82 05 }

  condition:
    any of them
}