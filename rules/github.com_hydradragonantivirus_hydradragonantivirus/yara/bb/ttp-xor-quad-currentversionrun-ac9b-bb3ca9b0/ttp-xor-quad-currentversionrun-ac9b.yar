rule TTP_XOR_QUAD_CurrentVersionRun_ac9b {
  strings:
    $key_ac9b = { ff f4 [2] db fa [2] f0 d6 [2] de f4 [2] ca ef [2] c5 f5 [2] db e8 [2] d9 e9 [2] c2 ef [2] de e8 [2] c2 c7 }

  condition:
    any of them
}