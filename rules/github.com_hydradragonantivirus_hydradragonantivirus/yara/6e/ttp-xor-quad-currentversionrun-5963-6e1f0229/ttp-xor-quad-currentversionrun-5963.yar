rule TTP_XOR_QUAD_CurrentVersionRun_5963 {
  strings:
    $key_5963 = { 0a 0c [2] 2e 02 [2] 05 2e [2] 2b 0c [2] 3f 17 [2] 30 0d [2] 2e 10 [2] 2c 11 [2] 37 17 [2] 2b 10 [2] 37 3f }

  condition:
    any of them
}