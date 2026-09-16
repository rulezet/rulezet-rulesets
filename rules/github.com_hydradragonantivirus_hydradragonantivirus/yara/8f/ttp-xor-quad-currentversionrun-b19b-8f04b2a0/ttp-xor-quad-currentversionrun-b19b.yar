rule TTP_XOR_QUAD_CurrentVersionRun_b19b {
  strings:
    $key_b19b = { e2 f4 [2] c6 fa [2] ed d6 [2] c3 f4 [2] d7 ef [2] d8 f5 [2] c6 e8 [2] c4 e9 [2] df ef [2] c3 e8 [2] df c7 }

  condition:
    any of them
}