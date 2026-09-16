rule TTP_XOR_QUAD_CurrentVersionRun_8fad {
  strings:
    $key_8fad = { dc c2 [2] f8 cc [2] d3 e0 [2] fd c2 [2] e9 d9 [2] e6 c3 [2] f8 de [2] fa df [2] e1 d9 [2] fd de [2] e1 f1 }

  condition:
    any of them
}