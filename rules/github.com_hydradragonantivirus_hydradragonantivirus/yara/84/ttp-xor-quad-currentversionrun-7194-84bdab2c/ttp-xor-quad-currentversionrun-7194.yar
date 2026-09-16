rule TTP_XOR_QUAD_CurrentVersionRun_7194 {
  strings:
    $key_7194 = { 22 fb [2] 06 f5 [2] 2d d9 [2] 03 fb [2] 17 e0 [2] 18 fa [2] 06 e7 [2] 04 e6 [2] 1f e0 [2] 03 e7 [2] 1f c8 }

  condition:
    any of them
}