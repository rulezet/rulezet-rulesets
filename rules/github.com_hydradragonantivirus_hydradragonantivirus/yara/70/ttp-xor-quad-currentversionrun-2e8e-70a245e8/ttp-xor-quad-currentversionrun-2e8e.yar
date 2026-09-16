rule TTP_XOR_QUAD_CurrentVersionRun_2e8e {
  strings:
    $key_2e8e = { 7d e1 [2] 59 ef [2] 72 c3 [2] 5c e1 [2] 48 fa [2] 47 e0 [2] 59 fd [2] 5b fc [2] 40 fa [2] 5c fd [2] 40 d2 }

  condition:
    any of them
}