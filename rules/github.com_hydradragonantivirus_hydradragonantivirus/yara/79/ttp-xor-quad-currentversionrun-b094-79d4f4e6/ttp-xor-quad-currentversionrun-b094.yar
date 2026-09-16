rule TTP_XOR_QUAD_CurrentVersionRun_b094 {
  strings:
    $key_b094 = { e3 fb [2] c7 f5 [2] ec d9 [2] c2 fb [2] d6 e0 [2] d9 fa [2] c7 e7 [2] c5 e6 [2] de e0 [2] c2 e7 [2] de c8 }

  condition:
    any of them
}