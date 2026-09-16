rule TTP_XOR_QUAD_CurrentVersionRun_3bd5 {
  strings:
    $key_3bd5 = { 68 ba [2] 4c b4 [2] 67 98 [2] 49 ba [2] 5d a1 [2] 52 bb [2] 4c a6 [2] 4e a7 [2] 55 a1 [2] 49 a6 [2] 55 89 }

  condition:
    any of them
}