rule TTP_XOR_QUAD_CurrentVersionRun_8188 {
  strings:
    $key_8188 = { d2 e7 [2] f6 e9 [2] dd c5 [2] f3 e7 [2] e7 fc [2] e8 e6 [2] f6 fb [2] f4 fa [2] ef fc [2] f3 fb [2] ef d4 }

  condition:
    any of them
}