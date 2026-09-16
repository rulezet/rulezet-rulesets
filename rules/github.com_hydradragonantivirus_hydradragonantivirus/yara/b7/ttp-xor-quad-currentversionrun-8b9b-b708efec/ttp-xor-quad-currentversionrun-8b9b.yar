rule TTP_XOR_QUAD_CurrentVersionRun_8b9b {
  strings:
    $key_8b9b = { d8 f4 [2] fc fa [2] d7 d6 [2] f9 f4 [2] ed ef [2] e2 f5 [2] fc e8 [2] fe e9 [2] e5 ef [2] f9 e8 [2] e5 c7 }

  condition:
    any of them
}