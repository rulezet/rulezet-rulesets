rule TTP_XOR_QUAD_CurrentVersionRun_3195 {
  strings:
    $key_3195 = { 62 fa [2] 46 f4 [2] 6d d8 [2] 43 fa [2] 57 e1 [2] 58 fb [2] 46 e6 [2] 44 e7 [2] 5f e1 [2] 43 e6 [2] 5f c9 }

  condition:
    any of them
}