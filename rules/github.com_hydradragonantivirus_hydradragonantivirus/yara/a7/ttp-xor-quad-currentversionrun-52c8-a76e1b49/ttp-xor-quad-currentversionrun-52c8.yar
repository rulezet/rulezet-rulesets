rule TTP_XOR_QUAD_CurrentVersionRun_52c8 {
  strings:
    $key_52c8 = { 01 a7 [2] 25 a9 [2] 0e 85 [2] 20 a7 [2] 34 bc [2] 3b a6 [2] 25 bb [2] 27 ba [2] 3c bc [2] 20 bb [2] 3c 94 }

  condition:
    any of them
}