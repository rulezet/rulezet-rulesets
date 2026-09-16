rule TTP_XOR_QUAD_CurrentVersionRun_59df {
  strings:
    $key_59df = { 0a b0 [2] 2e be [2] 05 92 [2] 2b b0 [2] 3f ab [2] 30 b1 [2] 2e ac [2] 2c ad [2] 37 ab [2] 2b ac [2] 37 83 }

  condition:
    any of them
}