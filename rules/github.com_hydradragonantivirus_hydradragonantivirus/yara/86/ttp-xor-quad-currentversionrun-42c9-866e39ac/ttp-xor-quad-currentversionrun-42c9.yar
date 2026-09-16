rule TTP_XOR_QUAD_CurrentVersionRun_42c9 {
  strings:
    $key_42c9 = { 11 a6 [2] 35 a8 [2] 1e 84 [2] 30 a6 [2] 24 bd [2] 2b a7 [2] 35 ba [2] 37 bb [2] 2c bd [2] 30 ba [2] 2c 95 }

  condition:
    any of them
}