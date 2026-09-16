rule TTP_XOR_QUAD_CurrentVersionRun_02c8 {
  strings:
    $key_02c8 = { 51 a7 [2] 75 a9 [2] 5e 85 [2] 70 a7 [2] 64 bc [2] 6b a6 [2] 75 bb [2] 77 ba [2] 6c bc [2] 70 bb [2] 6c 94 }

  condition:
    any of them
}