rule TTP_XOR_QUAD_CurrentVersionRun_f3a6 {
  strings:
    $key_f3a6 = { a0 c9 [2] 84 c7 [2] af eb [2] 81 c9 [2] 95 d2 [2] 9a c8 [2] 84 d5 [2] 86 d4 [2] 9d d2 [2] 81 d5 [2] 9d fa }

  condition:
    any of them
}