rule TTP_XOR_QUAD_CurrentVersionRun_b29b {
  strings:
    $key_b29b = { e1 f4 [2] c5 fa [2] ee d6 [2] c0 f4 [2] d4 ef [2] db f5 [2] c5 e8 [2] c7 e9 [2] dc ef [2] c0 e8 [2] dc c7 }

  condition:
    any of them
}