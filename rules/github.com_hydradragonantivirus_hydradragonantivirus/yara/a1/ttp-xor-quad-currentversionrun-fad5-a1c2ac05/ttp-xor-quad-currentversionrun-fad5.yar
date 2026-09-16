rule TTP_XOR_QUAD_CurrentVersionRun_fad5 {
  strings:
    $key_fad5 = { a9 ba [2] 8d b4 [2] a6 98 [2] 88 ba [2] 9c a1 [2] 93 bb [2] 8d a6 [2] 8f a7 [2] 94 a1 [2] 88 a6 [2] 94 89 }

  condition:
    any of them
}