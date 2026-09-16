rule TTP_XOR_QUAD_CurrentVersionRun_6ad5 {
  strings:
    $key_6ad5 = { 39 ba [2] 1d b4 [2] 36 98 [2] 18 ba [2] 0c a1 [2] 03 bb [2] 1d a6 [2] 1f a7 [2] 04 a1 [2] 18 a6 [2] 04 89 }

  condition:
    any of them
}