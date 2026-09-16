rule TTP_XOR_QUAD_CurrentVersionRun_0842 {
  strings:
    $key_0842 = { 5b 2d [2] 7f 23 [2] 54 0f [2] 7a 2d [2] 6e 36 [2] 61 2c [2] 7f 31 [2] 7d 30 [2] 66 36 [2] 7a 31 [2] 66 1e }

  condition:
    any of them
}