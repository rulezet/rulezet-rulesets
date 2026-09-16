rule TTP_XOR_QUAD_CurrentVersionRun_0ad4 {
  strings:
    $key_0ad4 = { 59 bb [2] 7d b5 [2] 56 99 [2] 78 bb [2] 6c a0 [2] 63 ba [2] 7d a7 [2] 7f a6 [2] 64 a0 [2] 78 a7 [2] 64 88 }

  condition:
    any of them
}