rule TTP_XOR_QUAD_CurrentVersionRun_5936 {
  strings:
    $key_5936 = { 0a 59 [2] 2e 57 [2] 05 7b [2] 2b 59 [2] 3f 42 [2] 30 58 [2] 2e 45 [2] 2c 44 [2] 37 42 [2] 2b 45 [2] 37 6a }

  condition:
    any of them
}