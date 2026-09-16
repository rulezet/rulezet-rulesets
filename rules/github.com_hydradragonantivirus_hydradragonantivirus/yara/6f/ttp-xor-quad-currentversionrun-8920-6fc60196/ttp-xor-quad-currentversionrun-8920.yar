rule TTP_XOR_QUAD_CurrentVersionRun_8920 {
  strings:
    $key_8920 = { da 4f [2] fe 41 [2] d5 6d [2] fb 4f [2] ef 54 [2] e0 4e [2] fe 53 [2] fc 52 [2] e7 54 [2] fb 53 [2] e7 7c }

  condition:
    any of them
}