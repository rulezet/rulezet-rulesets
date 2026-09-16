rule TTP_XOR_QUAD_CurrentVersionRun_25c2 {
  strings:
    $key_25c2 = { 76 ad [2] 52 a3 [2] 79 8f [2] 57 ad [2] 43 b6 [2] 4c ac [2] 52 b1 [2] 50 b0 [2] 4b b6 [2] 57 b1 [2] 4b 9e }

  condition:
    any of them
}