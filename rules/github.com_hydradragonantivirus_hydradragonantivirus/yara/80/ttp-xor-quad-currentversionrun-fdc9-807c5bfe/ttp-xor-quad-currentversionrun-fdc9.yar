rule TTP_XOR_QUAD_CurrentVersionRun_fdc9 {
  strings:
    $key_fdc9 = { ae a6 [2] 8a a8 [2] a1 84 [2] 8f a6 [2] 9b bd [2] 94 a7 [2] 8a ba [2] 88 bb [2] 93 bd [2] 8f ba [2] 93 95 }

  condition:
    any of them
}