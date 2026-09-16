rule TTP_XOR_QUAD_CurrentVersionRun_59e6 {
  strings:
    $key_59e6 = { 0a 89 [2] 2e 87 [2] 05 ab [2] 2b 89 [2] 3f 92 [2] 30 88 [2] 2e 95 [2] 2c 94 [2] 37 92 [2] 2b 95 [2] 37 ba }

  condition:
    any of them
}