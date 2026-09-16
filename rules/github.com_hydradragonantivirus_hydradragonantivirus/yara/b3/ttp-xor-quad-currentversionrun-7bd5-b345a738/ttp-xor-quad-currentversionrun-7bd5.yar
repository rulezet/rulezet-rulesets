rule TTP_XOR_QUAD_CurrentVersionRun_7bd5 {
  strings:
    $key_7bd5 = { 28 ba [2] 0c b4 [2] 27 98 [2] 09 ba [2] 1d a1 [2] 12 bb [2] 0c a6 [2] 0e a7 [2] 15 a1 [2] 09 a6 [2] 15 89 }

  condition:
    any of them
}