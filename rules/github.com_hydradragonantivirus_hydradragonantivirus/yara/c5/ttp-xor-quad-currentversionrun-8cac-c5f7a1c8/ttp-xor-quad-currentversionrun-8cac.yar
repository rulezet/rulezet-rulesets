rule TTP_XOR_QUAD_CurrentVersionRun_8cac {
  strings:
    $key_8cac = { df c3 [2] fb cd [2] d0 e1 [2] fe c3 [2] ea d8 [2] e5 c2 [2] fb df [2] f9 de [2] e2 d8 [2] fe df [2] e2 f0 }

  condition:
    any of them
}