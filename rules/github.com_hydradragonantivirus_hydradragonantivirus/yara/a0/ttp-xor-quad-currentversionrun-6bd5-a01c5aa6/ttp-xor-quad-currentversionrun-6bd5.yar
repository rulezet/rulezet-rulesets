rule TTP_XOR_QUAD_CurrentVersionRun_6bd5 {
  strings:
    $key_6bd5 = { 38 ba [2] 1c b4 [2] 37 98 [2] 19 ba [2] 0d a1 [2] 02 bb [2] 1c a6 [2] 1e a7 [2] 05 a1 [2] 19 a6 [2] 05 89 }

  condition:
    any of them
}