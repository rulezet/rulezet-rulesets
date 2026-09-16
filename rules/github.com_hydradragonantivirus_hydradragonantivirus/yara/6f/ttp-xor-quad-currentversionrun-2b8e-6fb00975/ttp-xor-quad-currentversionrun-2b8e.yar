rule TTP_XOR_QUAD_CurrentVersionRun_2b8e {
  strings:
    $key_2b8e = { 78 e1 [2] 5c ef [2] 77 c3 [2] 59 e1 [2] 4d fa [2] 42 e0 [2] 5c fd [2] 5e fc [2] 45 fa [2] 59 fd [2] 45 d2 }

  condition:
    any of them
}