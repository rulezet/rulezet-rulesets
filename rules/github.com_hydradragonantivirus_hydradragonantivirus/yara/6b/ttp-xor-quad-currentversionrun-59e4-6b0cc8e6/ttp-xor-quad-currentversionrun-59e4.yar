rule TTP_XOR_QUAD_CurrentVersionRun_59e4 {
  strings:
    $key_59e4 = { 0a 8b [2] 2e 85 [2] 05 a9 [2] 2b 8b [2] 3f 90 [2] 30 8a [2] 2e 97 [2] 2c 96 [2] 37 90 [2] 2b 97 [2] 37 b8 }

  condition:
    any of them
}