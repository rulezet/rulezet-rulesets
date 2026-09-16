rule TTP_XOR_QUAD_CurrentVersionRun_89fd {
  strings:
    $key_89fd = { da 92 [2] fe 9c [2] d5 b0 [2] fb 92 [2] ef 89 [2] e0 93 [2] fe 8e [2] fc 8f [2] e7 89 [2] fb 8e [2] e7 a1 }

  condition:
    any of them
}