rule TTP_XOR_QUAD_CurrentVersionRun_92c9 {
  strings:
    $key_92c9 = { c1 a6 [2] e5 a8 [2] ce 84 [2] e0 a6 [2] f4 bd [2] fb a7 [2] e5 ba [2] e7 bb [2] fc bd [2] e0 ba [2] fc 95 }

  condition:
    any of them
}