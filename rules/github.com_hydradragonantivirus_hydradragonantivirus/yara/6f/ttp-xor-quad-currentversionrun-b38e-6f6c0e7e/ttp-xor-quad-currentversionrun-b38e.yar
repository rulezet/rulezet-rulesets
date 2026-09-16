rule TTP_XOR_QUAD_CurrentVersionRun_b38e {
  strings:
    $key_b38e = { e0 e1 [2] c4 ef [2] ef c3 [2] c1 e1 [2] d5 fa [2] da e0 [2] c4 fd [2] c6 fc [2] dd fa [2] c1 fd [2] dd d2 }

  condition:
    any of them
}