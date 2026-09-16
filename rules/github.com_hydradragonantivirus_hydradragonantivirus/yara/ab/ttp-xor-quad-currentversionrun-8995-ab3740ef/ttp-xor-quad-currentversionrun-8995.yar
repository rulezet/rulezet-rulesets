rule TTP_XOR_QUAD_CurrentVersionRun_8995 {
  strings:
    $key_8995 = { da fa [2] fe f4 [2] d5 d8 [2] fb fa [2] ef e1 [2] e0 fb [2] fe e6 [2] fc e7 [2] e7 e1 [2] fb e6 [2] e7 c9 }

  condition:
    any of them
}