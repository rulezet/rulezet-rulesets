rule TTP_XOR_QUAD_CurrentVersionRun_5194 {
  strings:
    $key_5194 = { 02 fb [2] 26 f5 [2] 0d d9 [2] 23 fb [2] 37 e0 [2] 38 fa [2] 26 e7 [2] 24 e6 [2] 3f e0 [2] 23 e7 [2] 3f c8 }

  condition:
    any of them
}