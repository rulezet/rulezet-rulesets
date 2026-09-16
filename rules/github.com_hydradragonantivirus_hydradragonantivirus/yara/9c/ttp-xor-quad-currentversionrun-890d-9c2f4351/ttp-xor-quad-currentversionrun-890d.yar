rule TTP_XOR_QUAD_CurrentVersionRun_890d {
  strings:
    $key_890d = { da 62 [2] fe 6c [2] d5 40 [2] fb 62 [2] ef 79 [2] e0 63 [2] fe 7e [2] fc 7f [2] e7 79 [2] fb 7e [2] e7 51 }

  condition:
    any of them
}