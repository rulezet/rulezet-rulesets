rule TTP_XOR_QUAD_CurrentVersionRun_69df {
  strings:
    $key_69df = { 3a b0 [2] 1e be [2] 35 92 [2] 1b b0 [2] 0f ab [2] 00 b1 [2] 1e ac [2] 1c ad [2] 07 ab [2] 1b ac [2] 07 83 }

  condition:
    any of them
}