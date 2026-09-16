rule TTP_XOR_QUAD_CurrentVersionRun_8997 {
  strings:
    $key_8997 = { da f8 [2] fe f6 [2] d5 da [2] fb f8 [2] ef e3 [2] e0 f9 [2] fe e4 [2] fc e5 [2] e7 e3 [2] fb e4 [2] e7 cb }

  condition:
    any of them
}