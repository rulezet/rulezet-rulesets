rule TTP_XOR_QUAD_CurrentVersionRun_f6c9 {
  strings:
    $key_f6c9 = { a5 a6 [2] 81 a8 [2] aa 84 [2] 84 a6 [2] 90 bd [2] 9f a7 [2] 81 ba [2] 83 bb [2] 98 bd [2] 84 ba [2] 98 95 }

  condition:
    any of them
}