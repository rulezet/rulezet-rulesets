rule TTP_XOR_QUAD_CurrentVersionRun_8993 {
  strings:
    $key_8993 = { da fc [2] fe f2 [2] d5 de [2] fb fc [2] ef e7 [2] e0 fd [2] fe e0 [2] fc e1 [2] e7 e7 [2] fb e0 [2] e7 cf }

  condition:
    any of them
}