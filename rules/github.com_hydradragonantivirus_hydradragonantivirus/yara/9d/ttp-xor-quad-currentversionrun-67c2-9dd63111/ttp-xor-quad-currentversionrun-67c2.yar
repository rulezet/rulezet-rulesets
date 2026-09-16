rule TTP_XOR_QUAD_CurrentVersionRun_67c2 {
  strings:
    $key_67c2 = { 34 ad [2] 10 a3 [2] 3b 8f [2] 15 ad [2] 01 b6 [2] 0e ac [2] 10 b1 [2] 12 b0 [2] 09 b6 [2] 15 b1 [2] 09 9e }

  condition:
    any of them
}