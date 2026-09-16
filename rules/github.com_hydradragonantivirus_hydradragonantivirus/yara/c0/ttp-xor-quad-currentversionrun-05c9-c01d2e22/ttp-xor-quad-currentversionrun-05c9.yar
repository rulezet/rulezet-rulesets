rule TTP_XOR_QUAD_CurrentVersionRun_05c9 {
  strings:
    $key_05c9 = { 56 a6 [2] 72 a8 [2] 59 84 [2] 77 a6 [2] 63 bd [2] 6c a7 [2] 72 ba [2] 70 bb [2] 6b bd [2] 77 ba [2] 6b 95 }

  condition:
    any of them
}