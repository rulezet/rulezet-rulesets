rule TTP_XOR_QUAD_CurrentVersionRun_89ad {
  strings:
    $key_89ad = { da c2 [2] fe cc [2] d5 e0 [2] fb c2 [2] ef d9 [2] e0 c3 [2] fe de [2] fc df [2] e7 d9 [2] fb de [2] e7 f1 }

  condition:
    any of them
}