rule TTP_XOR_QUAD_CurrentVersionRun_a79b {
  strings:
    $key_a79b = { f4 f4 [2] d0 fa [2] fb d6 [2] d5 f4 [2] c1 ef [2] ce f5 [2] d0 e8 [2] d2 e9 [2] c9 ef [2] d5 e8 [2] c9 c7 }

  condition:
    any of them
}