rule TTP_XOR_QUAD_CurrentVersionRun_83c9 {
  strings:
    $key_83c9 = { d0 a6 [2] f4 a8 [2] df 84 [2] f1 a6 [2] e5 bd [2] ea a7 [2] f4 ba [2] f6 bb [2] ed bd [2] f1 ba [2] ed 95 }

  condition:
    any of them
}