rule TTP_XOR_QUAD_CurrentVersionRun_8990 {
  strings:
    $key_8990 = { da ff [2] fe f1 [2] d5 dd [2] fb ff [2] ef e4 [2] e0 fe [2] fe e3 [2] fc e2 [2] e7 e4 [2] fb e3 [2] e7 cc }

  condition:
    any of them
}