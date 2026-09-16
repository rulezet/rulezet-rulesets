rule TTP_XOR_QUAD_CurrentVersionRun_ec48 {
  strings:
    $key_ec48 = { bf 27 [2] 9b 29 [2] b0 05 [2] 9e 27 [2] 8a 3c [2] 85 26 [2] 9b 3b [2] 99 3a [2] 82 3c [2] 9e 3b [2] 82 14 }

  condition:
    any of them
}