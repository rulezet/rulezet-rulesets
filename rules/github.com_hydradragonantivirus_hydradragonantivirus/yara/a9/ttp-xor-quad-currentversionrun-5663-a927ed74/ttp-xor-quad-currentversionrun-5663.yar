rule TTP_XOR_QUAD_CurrentVersionRun_5663 {
  strings:
    $key_5663 = { 05 0c [2] 21 02 [2] 0a 2e [2] 24 0c [2] 30 17 [2] 3f 0d [2] 21 10 [2] 23 11 [2] 38 17 [2] 24 10 [2] 38 3f }

  condition:
    any of them
}