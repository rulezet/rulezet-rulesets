rule TTP_XOR_QUAD_CurrentVersionRun_a58e {
  strings:
    $key_a58e = { f6 e1 [2] d2 ef [2] f9 c3 [2] d7 e1 [2] c3 fa [2] cc e0 [2] d2 fd [2] d0 fc [2] cb fa [2] d7 fd [2] cb d2 }

  condition:
    any of them
}