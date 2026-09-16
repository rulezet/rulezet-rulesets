rule TTP_XOR_QUAD_CurrentVersionRun_89ed {
  strings:
    $key_89ed = { da 82 [2] fe 8c [2] d5 a0 [2] fb 82 [2] ef 99 [2] e0 83 [2] fe 9e [2] fc 9f [2] e7 99 [2] fb 9e [2] e7 b1 }

  condition:
    any of them
}