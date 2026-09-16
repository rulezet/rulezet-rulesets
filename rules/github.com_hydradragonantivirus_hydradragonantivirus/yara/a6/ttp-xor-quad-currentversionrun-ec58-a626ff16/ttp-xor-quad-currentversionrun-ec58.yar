rule TTP_XOR_QUAD_CurrentVersionRun_ec58 {
  strings:
    $key_ec58 = { bf 37 [2] 9b 39 [2] b0 15 [2] 9e 37 [2] 8a 2c [2] 85 36 [2] 9b 2b [2] 99 2a [2] 82 2c [2] 9e 2b [2] 82 04 }

  condition:
    any of them
}