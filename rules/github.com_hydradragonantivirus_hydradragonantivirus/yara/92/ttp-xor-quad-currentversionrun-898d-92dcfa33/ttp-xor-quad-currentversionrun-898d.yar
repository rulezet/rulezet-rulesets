rule TTP_XOR_QUAD_CurrentVersionRun_898d {
  strings:
    $key_898d = { da e2 [2] fe ec [2] d5 c0 [2] fb e2 [2] ef f9 [2] e0 e3 [2] fe fe [2] fc ff [2] e7 f9 [2] fb fe [2] e7 d1 }

  condition:
    any of them
}