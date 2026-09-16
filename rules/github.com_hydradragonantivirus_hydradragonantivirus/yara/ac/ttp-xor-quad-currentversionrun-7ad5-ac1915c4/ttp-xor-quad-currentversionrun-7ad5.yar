rule TTP_XOR_QUAD_CurrentVersionRun_7ad5 {
  strings:
    $key_7ad5 = { 29 ba [2] 0d b4 [2] 26 98 [2] 08 ba [2] 1c a1 [2] 13 bb [2] 0d a6 [2] 0f a7 [2] 14 a1 [2] 08 a6 [2] 14 89 }

  condition:
    any of them
}