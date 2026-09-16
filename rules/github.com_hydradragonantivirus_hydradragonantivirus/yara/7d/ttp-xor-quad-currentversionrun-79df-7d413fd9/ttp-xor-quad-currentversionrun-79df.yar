rule TTP_XOR_QUAD_CurrentVersionRun_79df {
  strings:
    $key_79df = { 2a b0 [2] 0e be [2] 25 92 [2] 0b b0 [2] 1f ab [2] 10 b1 [2] 0e ac [2] 0c ad [2] 17 ab [2] 0b ac [2] 17 83 }

  condition:
    any of them
}