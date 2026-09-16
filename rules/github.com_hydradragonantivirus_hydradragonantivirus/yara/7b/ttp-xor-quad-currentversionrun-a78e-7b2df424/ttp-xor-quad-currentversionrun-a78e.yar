rule TTP_XOR_QUAD_CurrentVersionRun_a78e {
  strings:
    $key_a78e = { f4 e1 [2] d0 ef [2] fb c3 [2] d5 e1 [2] c1 fa [2] ce e0 [2] d0 fd [2] d2 fc [2] c9 fa [2] d5 fd [2] c9 d2 }

  condition:
    any of them
}