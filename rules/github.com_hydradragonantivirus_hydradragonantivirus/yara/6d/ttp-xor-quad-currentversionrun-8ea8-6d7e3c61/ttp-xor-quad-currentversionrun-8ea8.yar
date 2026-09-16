rule TTP_XOR_QUAD_CurrentVersionRun_8ea8 {
  strings:
    $key_8ea8 = { dd c7 [2] f9 c9 [2] d2 e5 [2] fc c7 [2] e8 dc [2] e7 c6 [2] f9 db [2] fb da [2] e0 dc [2] fc db [2] e0 f4 }

  condition:
    any of them
}