rule TTP_XOR_QUAD_CurrentVersionRun_23c9 {
  strings:
    $key_23c9 = { 70 a6 [2] 54 a8 [2] 7f 84 [2] 51 a6 [2] 45 bd [2] 4a a7 [2] 54 ba [2] 56 bb [2] 4d bd [2] 51 ba [2] 4d 95 }

  condition:
    any of them
}