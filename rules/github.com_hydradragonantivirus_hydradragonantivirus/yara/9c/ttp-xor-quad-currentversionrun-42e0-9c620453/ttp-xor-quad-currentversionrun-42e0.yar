rule TTP_XOR_QUAD_CurrentVersionRun_42e0 {
  strings:
    $key_42e0 = { 11 8f [2] 35 81 [2] 1e ad [2] 30 8f [2] 24 94 [2] 2b 8e [2] 35 93 [2] 37 92 [2] 2c 94 [2] 30 93 [2] 2c bc }

  condition:
    any of them
}