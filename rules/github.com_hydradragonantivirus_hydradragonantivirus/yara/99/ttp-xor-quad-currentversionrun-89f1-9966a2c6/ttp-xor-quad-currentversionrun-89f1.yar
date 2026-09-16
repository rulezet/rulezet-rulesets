rule TTP_XOR_QUAD_CurrentVersionRun_89f1 {
  strings:
    $key_89f1 = { da 9e [2] fe 90 [2] d5 bc [2] fb 9e [2] ef 85 [2] e0 9f [2] fe 82 [2] fc 83 [2] e7 85 [2] fb 82 [2] e7 ad }

  condition:
    any of them
}