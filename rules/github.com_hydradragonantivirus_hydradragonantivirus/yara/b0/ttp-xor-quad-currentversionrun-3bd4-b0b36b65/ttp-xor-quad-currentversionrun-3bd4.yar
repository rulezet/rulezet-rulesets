rule TTP_XOR_QUAD_CurrentVersionRun_3bd4 {
  strings:
    $key_3bd4 = { 68 bb [2] 4c b5 [2] 67 99 [2] 49 bb [2] 5d a0 [2] 52 ba [2] 4c a7 [2] 4e a6 [2] 55 a0 [2] 49 a7 [2] 55 88 }

  condition:
    any of them
}