rule TTP_XOR_QUAD_CurrentVersionRun_ec5b {
  strings:
    $key_ec5b = { bf 34 [2] 9b 3a [2] b0 16 [2] 9e 34 [2] 8a 2f [2] 85 35 [2] 9b 28 [2] 99 29 [2] 82 2f [2] 9e 28 [2] 82 07 }

  condition:
    any of them
}