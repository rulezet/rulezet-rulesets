rule TTP_XOR_QUAD_CurrentVersionRun_89ba {
  strings:
    $key_89ba = { da d5 [2] fe db [2] d5 f7 [2] fb d5 [2] ef ce [2] e0 d4 [2] fe c9 [2] fc c8 [2] e7 ce [2] fb c9 [2] e7 e6 }

  condition:
    any of them
}