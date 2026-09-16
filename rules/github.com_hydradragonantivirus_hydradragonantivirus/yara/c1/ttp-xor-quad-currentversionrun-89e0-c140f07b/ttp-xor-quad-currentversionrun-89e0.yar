rule TTP_XOR_QUAD_CurrentVersionRun_89e0 {
  strings:
    $key_89e0 = { da 8f [2] fe 81 [2] d5 ad [2] fb 8f [2] ef 94 [2] e0 8e [2] fe 93 [2] fc 92 [2] e7 94 [2] fb 93 [2] e7 bc }

  condition:
    any of them
}