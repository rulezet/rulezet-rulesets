rule TTP_XOR_QUAD_CurrentVersionRun_8991 {
  strings:
    $key_8991 = { da fe [2] fe f0 [2] d5 dc [2] fb fe [2] ef e5 [2] e0 ff [2] fe e2 [2] fc e3 [2] e7 e5 [2] fb e2 [2] e7 cd }

  condition:
    any of them
}