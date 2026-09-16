rule TTP_XOR_QUAD_CurrentVersionRun_e7c2 {
  strings:
    $key_e7c2 = { b4 ad [2] 90 a3 [2] bb 8f [2] 95 ad [2] 81 b6 [2] 8e ac [2] 90 b1 [2] 92 b0 [2] 89 b6 [2] 95 b1 [2] 89 9e }

  condition:
    any of them
}