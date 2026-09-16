rule TTP_XOR_QUAD_CurrentVersionRun_b09b {
  strings:
    $key_b09b = { e3 f4 [2] c7 fa [2] ec d6 [2] c2 f4 [2] d6 ef [2] d9 f5 [2] c7 e8 [2] c5 e9 [2] de ef [2] c2 e8 [2] de c7 }

  condition:
    any of them
}