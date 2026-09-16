rule TTP_XOR_QUAD_CurrentVersionRun_8986 {
  strings:
    $key_8986 = { da e9 [2] fe e7 [2] d5 cb [2] fb e9 [2] ef f2 [2] e0 e8 [2] fe f5 [2] fc f4 [2] e7 f2 [2] fb f5 [2] e7 da }

  condition:
    any of them
}