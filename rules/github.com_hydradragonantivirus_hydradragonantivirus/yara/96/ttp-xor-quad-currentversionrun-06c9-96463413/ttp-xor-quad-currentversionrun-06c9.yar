rule TTP_XOR_QUAD_CurrentVersionRun_06c9 {
  strings:
    $key_06c9 = { 55 a6 [2] 71 a8 [2] 5a 84 [2] 74 a6 [2] 60 bd [2] 6f a7 [2] 71 ba [2] 73 bb [2] 68 bd [2] 74 ba [2] 68 95 }

  condition:
    any of them
}