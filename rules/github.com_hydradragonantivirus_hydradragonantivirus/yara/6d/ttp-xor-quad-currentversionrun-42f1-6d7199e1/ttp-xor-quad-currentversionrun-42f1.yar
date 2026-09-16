rule TTP_XOR_QUAD_CurrentVersionRun_42f1 {
  strings:
    $key_42f1 = { 11 9e [2] 35 90 [2] 1e bc [2] 30 9e [2] 24 85 [2] 2b 9f [2] 35 82 [2] 37 83 [2] 2c 85 [2] 30 82 [2] 2c ad }

  condition:
    any of them
}