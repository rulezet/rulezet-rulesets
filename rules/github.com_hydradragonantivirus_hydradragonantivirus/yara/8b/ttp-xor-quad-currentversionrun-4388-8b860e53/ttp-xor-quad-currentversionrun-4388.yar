rule TTP_XOR_QUAD_CurrentVersionRun_4388 {
  strings:
    $key_4388 = { 10 e7 [2] 34 e9 [2] 1f c5 [2] 31 e7 [2] 25 fc [2] 2a e6 [2] 34 fb [2] 36 fa [2] 2d fc [2] 31 fb [2] 2d d4 }

  condition:
    any of them
}