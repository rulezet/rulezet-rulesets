rule TTP_XOR_QUAD_CurrentVersionRun_f6b5 {
  strings:
    $key_f6b5 = { a5 da [2] 81 d4 [2] aa f8 [2] 84 da [2] 90 c1 [2] 9f db [2] 81 c6 [2] 83 c7 [2] 98 c1 [2] 84 c6 [2] 98 e9 }

  condition:
    any of them
}