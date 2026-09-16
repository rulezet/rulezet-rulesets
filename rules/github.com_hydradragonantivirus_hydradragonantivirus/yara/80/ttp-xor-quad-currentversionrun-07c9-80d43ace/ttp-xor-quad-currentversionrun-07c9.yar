rule TTP_XOR_QUAD_CurrentVersionRun_07c9 {
  strings:
    $key_07c9 = { 54 a6 [2] 70 a8 [2] 5b 84 [2] 75 a6 [2] 61 bd [2] 6e a7 [2] 70 ba [2] 72 bb [2] 69 bd [2] 75 ba [2] 69 95 }

  condition:
    any of them
}