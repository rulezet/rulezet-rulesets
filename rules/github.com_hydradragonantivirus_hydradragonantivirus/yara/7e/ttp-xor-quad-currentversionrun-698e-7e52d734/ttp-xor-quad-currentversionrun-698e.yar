rule TTP_XOR_QUAD_CurrentVersionRun_698e {
  strings:
    $key_698e = { 3a e1 [2] 1e ef [2] 35 c3 [2] 1b e1 [2] 0f fa [2] 00 e0 [2] 1e fd [2] 1c fc [2] 07 fa [2] 1b fd [2] 07 d2 }

  condition:
    any of them
}