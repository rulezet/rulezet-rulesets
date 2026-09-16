rule TTP_XOR_QUAD_CurrentVersionRun_36c8 {
  strings:
    $key_36c8 = { 65 a7 [2] 41 a9 [2] 6a 85 [2] 44 a7 [2] 50 bc [2] 5f a6 [2] 41 bb [2] 43 ba [2] 58 bc [2] 44 bb [2] 58 94 }

  condition:
    any of them
}