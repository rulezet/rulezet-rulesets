rule TTP_XOR_QUAD_CurrentVersionRun_95ed {
  strings:
    $key_95ed = { c6 82 [2] e2 8c [2] c9 a0 [2] e7 82 [2] f3 99 [2] fc 83 [2] e2 9e [2] e0 9f [2] fb 99 [2] e7 9e [2] fb b1 }

  condition:
    any of them
}