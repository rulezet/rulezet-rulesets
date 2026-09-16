rule TTP_XOR_QUAD_CurrentVersionRun_59e8 {
  strings:
    $key_59e8 = { 0a 87 [2] 2e 89 [2] 05 a5 [2] 2b 87 [2] 3f 9c [2] 30 86 [2] 2e 9b [2] 2c 9a [2] 37 9c [2] 2b 9b [2] 37 b4 }

  condition:
    any of them
}