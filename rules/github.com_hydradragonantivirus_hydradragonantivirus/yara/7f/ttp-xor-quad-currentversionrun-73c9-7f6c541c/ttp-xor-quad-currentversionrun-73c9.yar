rule TTP_XOR_QUAD_CurrentVersionRun_73c9 {
  strings:
    $key_73c9 = { 20 a6 [2] 04 a8 [2] 2f 84 [2] 01 a6 [2] 15 bd [2] 1a a7 [2] 04 ba [2] 06 bb [2] 1d bd [2] 01 ba [2] 1d 95 }

  condition:
    any of them
}