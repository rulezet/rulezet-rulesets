rule TTP_XOR_QUAD_CurrentVersionRun_59e1 {
  strings:
    $key_59e1 = { 0a 8e [2] 2e 80 [2] 05 ac [2] 2b 8e [2] 3f 95 [2] 30 8f [2] 2e 92 [2] 2c 93 [2] 37 95 [2] 2b 92 [2] 37 bd }

  condition:
    any of them
}