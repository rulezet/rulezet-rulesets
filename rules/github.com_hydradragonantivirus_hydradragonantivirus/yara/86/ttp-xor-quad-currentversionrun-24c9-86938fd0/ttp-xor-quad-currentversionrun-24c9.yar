rule TTP_XOR_QUAD_CurrentVersionRun_24c9 {
  strings:
    $key_24c9 = { 77 a6 [2] 53 a8 [2] 78 84 [2] 56 a6 [2] 42 bd [2] 4d a7 [2] 53 ba [2] 51 bb [2] 4a bd [2] 56 ba [2] 4a 95 }

  condition:
    any of them
}