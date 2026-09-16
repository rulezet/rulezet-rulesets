rule TTP_XOR_QUAD_CurrentVersionRun_14c9 {
  strings:
    $key_14c9 = { 47 a6 [2] 63 a8 [2] 48 84 [2] 66 a6 [2] 72 bd [2] 7d a7 [2] 63 ba [2] 61 bb [2] 7a bd [2] 66 ba [2] 7a 95 }

  condition:
    any of them
}