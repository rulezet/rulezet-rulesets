rule TTP_XOR_QUAD_CurrentVersionRun_74d2 {
  strings:
    $key_74d2 = { 27 bd [2] 03 b3 [2] 28 9f [2] 06 bd [2] 12 a6 [2] 1d bc [2] 03 a1 [2] 01 a0 [2] 1a a6 [2] 06 a1 [2] 1a 8e }

  condition:
    any of them
}