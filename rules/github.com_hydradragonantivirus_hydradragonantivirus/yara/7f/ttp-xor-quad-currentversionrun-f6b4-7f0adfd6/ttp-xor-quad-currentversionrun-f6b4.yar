rule TTP_XOR_QUAD_CurrentVersionRun_f6b4 {
  strings:
    $key_f6b4 = { a5 db [2] 81 d5 [2] aa f9 [2] 84 db [2] 90 c0 [2] 9f da [2] 81 c7 [2] 83 c6 [2] 98 c0 [2] 84 c7 [2] 98 e8 }

  condition:
    any of them
}