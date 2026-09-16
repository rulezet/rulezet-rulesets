rule TTP_XOR_QUAD_CurrentVersionRun_89ac {
  strings:
    $key_89ac = { da c3 [2] fe cd [2] d5 e1 [2] fb c3 [2] ef d8 [2] e0 c2 [2] fe df [2] fc de [2] e7 d8 [2] fb df [2] e7 f0 }

  condition:
    any of them
}