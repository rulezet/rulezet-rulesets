rule TTP_XOR_QUAD_CurrentVersionRun_f6c2 {
  strings:
    $key_f6c2 = { a5 ad [2] 81 a3 [2] aa 8f [2] 84 ad [2] 90 b6 [2] 9f ac [2] 81 b1 [2] 83 b0 [2] 98 b6 [2] 84 b1 [2] 98 9e }

  condition:
    any of them
}