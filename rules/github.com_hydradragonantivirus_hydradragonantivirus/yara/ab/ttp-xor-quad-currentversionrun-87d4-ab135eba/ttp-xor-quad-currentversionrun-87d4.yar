rule TTP_XOR_QUAD_CurrentVersionRun_87d4 {
  strings:
    $key_87d4 = { d4 bb [2] f0 b5 [2] db 99 [2] f5 bb [2] e1 a0 [2] ee ba [2] f0 a7 [2] f2 a6 [2] e9 a0 [2] f5 a7 [2] e9 88 }

  condition:
    any of them
}