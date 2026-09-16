rule TTP_XOR_QUAD_CurrentVersionRun_7ad4 {
  strings:
    $key_7ad4 = { 29 bb [2] 0d b5 [2] 26 99 [2] 08 bb [2] 1c a0 [2] 13 ba [2] 0d a7 [2] 0f a6 [2] 14 a0 [2] 08 a7 [2] 14 88 }

  condition:
    any of them
}