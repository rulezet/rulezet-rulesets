rule TTP_XOR_QUAD_CurrentVersionRun_2ac8 {
  strings:
    $key_2ac8 = { 79 a7 [2] 5d a9 [2] 76 85 [2] 58 a7 [2] 4c bc [2] 43 a6 [2] 5d bb [2] 5f ba [2] 44 bc [2] 58 bb [2] 44 94 }

  condition:
    any of them
}