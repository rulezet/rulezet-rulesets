rule TTP_XOR_QUAD_CurrentVersionRun_0388 {
  strings:
    $key_0388 = { 50 e7 [2] 74 e9 [2] 5f c5 [2] 71 e7 [2] 65 fc [2] 6a e6 [2] 74 fb [2] 76 fa [2] 6d fc [2] 71 fb [2] 6d d4 }

  condition:
    any of them
}