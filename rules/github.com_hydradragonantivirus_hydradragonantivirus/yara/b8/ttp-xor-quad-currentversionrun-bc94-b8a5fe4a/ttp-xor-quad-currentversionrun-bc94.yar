rule TTP_XOR_QUAD_CurrentVersionRun_bc94 {
  strings:
    $key_bc94 = { ef fb [2] cb f5 [2] e0 d9 [2] ce fb [2] da e0 [2] d5 fa [2] cb e7 [2] c9 e6 [2] d2 e0 [2] ce e7 [2] d2 c8 }

  condition:
    any of them
}