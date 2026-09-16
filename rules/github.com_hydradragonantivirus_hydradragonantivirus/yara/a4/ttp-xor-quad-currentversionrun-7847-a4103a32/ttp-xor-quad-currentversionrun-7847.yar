rule TTP_XOR_QUAD_CurrentVersionRun_7847 {
  strings:
    $key_7847 = { 2b 28 [2] 0f 26 [2] 24 0a [2] 0a 28 [2] 1e 33 [2] 11 29 [2] 0f 34 [2] 0d 35 [2] 16 33 [2] 0a 34 [2] 16 1b }

  condition:
    any of them
}