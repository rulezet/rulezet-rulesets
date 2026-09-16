rule TTP_XOR_QUAD_CurrentVersionRun_2ad5 {
  strings:
    $key_2ad5 = { 79 ba [2] 5d b4 [2] 76 98 [2] 58 ba [2] 4c a1 [2] 43 bb [2] 5d a6 [2] 5f a7 [2] 44 a1 [2] 58 a6 [2] 44 89 }

  condition:
    any of them
}