rule TTP_XOR_QUAD_CurrentVersionRun_f395 {
  strings:
    $key_f395 = { a0 fa [2] 84 f4 [2] af d8 [2] 81 fa [2] 95 e1 [2] 9a fb [2] 84 e6 [2] 86 e7 [2] 9d e1 [2] 81 e6 [2] 9d c9 }

  condition:
    any of them
}