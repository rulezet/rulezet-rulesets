rule TTP_XOR_QUAD_CurrentVersionRun_f7c9 {
  strings:
    $key_f7c9 = { a4 a6 [2] 80 a8 [2] ab 84 [2] 85 a6 [2] 91 bd [2] 9e a7 [2] 80 ba [2] 82 bb [2] 99 bd [2] 85 ba [2] 99 95 }

  condition:
    any of them
}