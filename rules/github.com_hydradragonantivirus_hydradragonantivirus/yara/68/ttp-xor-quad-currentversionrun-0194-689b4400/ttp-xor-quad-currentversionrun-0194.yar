rule TTP_XOR_QUAD_CurrentVersionRun_0194 {
  strings:
    $key_0194 = { 52 fb [2] 76 f5 [2] 5d d9 [2] 73 fb [2] 67 e0 [2] 68 fa [2] 76 e7 [2] 74 e6 [2] 6f e0 [2] 73 e7 [2] 6f c8 }

  condition:
    any of them
}