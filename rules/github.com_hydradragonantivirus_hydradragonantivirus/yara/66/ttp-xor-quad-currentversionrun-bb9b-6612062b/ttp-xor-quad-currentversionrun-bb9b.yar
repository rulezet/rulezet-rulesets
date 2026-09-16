rule TTP_XOR_QUAD_CurrentVersionRun_bb9b {
  strings:
    $key_bb9b = { e8 f4 [2] cc fa [2] e7 d6 [2] c9 f4 [2] dd ef [2] d2 f5 [2] cc e8 [2] ce e9 [2] d5 ef [2] c9 e8 [2] d5 c7 }

  condition:
    any of them
}