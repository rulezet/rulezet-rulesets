rule TTP_XOR_QUAD_CurrentVersionRun_5389 {
  strings:
    $key_5389 = { 00 e6 [2] 24 e8 [2] 0f c4 [2] 21 e6 [2] 35 fd [2] 3a e7 [2] 24 fa [2] 26 fb [2] 3d fd [2] 21 fa [2] 3d d5 }

  condition:
    any of them
}