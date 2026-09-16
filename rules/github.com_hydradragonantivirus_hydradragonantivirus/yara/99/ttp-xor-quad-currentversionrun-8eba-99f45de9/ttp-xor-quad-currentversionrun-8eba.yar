rule TTP_XOR_QUAD_CurrentVersionRun_8eba {
  strings:
    $key_8eba = { dd d5 [2] f9 db [2] d2 f7 [2] fc d5 [2] e8 ce [2] e7 d4 [2] f9 c9 [2] fb c8 [2] e0 ce [2] fc c9 [2] e0 e6 }

  condition:
    any of them
}