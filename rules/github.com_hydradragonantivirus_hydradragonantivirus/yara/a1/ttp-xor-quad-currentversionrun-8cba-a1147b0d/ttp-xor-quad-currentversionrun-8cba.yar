rule TTP_XOR_QUAD_CurrentVersionRun_8cba {
  strings:
    $key_8cba = { df d5 [2] fb db [2] d0 f7 [2] fe d5 [2] ea ce [2] e5 d4 [2] fb c9 [2] f9 c8 [2] e2 ce [2] fe c9 [2] e2 e6 }

  condition:
    any of them
}