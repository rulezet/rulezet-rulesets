rule TTP_XOR_QUAD_CurrentVersionRun_51c9 {
  strings:
    $key_51c9 = { 02 a6 [2] 26 a8 [2] 0d 84 [2] 23 a6 [2] 37 bd [2] 38 a7 [2] 26 ba [2] 24 bb [2] 3f bd [2] 23 ba [2] 3f 95 }

  condition:
    any of them
}