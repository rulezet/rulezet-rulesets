rule TTP_XOR_QUAD_CurrentVersionRun_89ef {
  strings:
    $key_89ef = { da 80 [2] fe 8e [2] d5 a2 [2] fb 80 [2] ef 9b [2] e0 81 [2] fe 9c [2] fc 9d [2] e7 9b [2] fb 9c [2] e7 b3 }

  condition:
    any of them
}