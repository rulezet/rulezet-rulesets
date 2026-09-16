rule TTP_XOR_QUAD_CurrentVersionRun_89dd {
  strings:
    $key_89dd = { da b2 [2] fe bc [2] d5 90 [2] fb b2 [2] ef a9 [2] e0 b3 [2] fe ae [2] fc af [2] e7 a9 [2] fb ae [2] e7 81 }

  condition:
    any of them
}