rule TTP_XOR_QUAD_CurrentVersionRun_308e {
  strings:
    $key_308e = { 63 e1 [2] 47 ef [2] 6c c3 [2] 42 e1 [2] 56 fa [2] 59 e0 [2] 47 fd [2] 45 fc [2] 5e fa [2] 42 fd [2] 5e d2 }

  condition:
    any of them
}