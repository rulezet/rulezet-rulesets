rule TTP_XOR_QUAD_CurrentVersionRun_33c9 {
  strings:
    $key_33c9 = { 60 a6 [2] 44 a8 [2] 6f 84 [2] 41 a6 [2] 55 bd [2] 5a a7 [2] 44 ba [2] 46 bb [2] 5d bd [2] 41 ba [2] 5d 95 }

  condition:
    any of them
}