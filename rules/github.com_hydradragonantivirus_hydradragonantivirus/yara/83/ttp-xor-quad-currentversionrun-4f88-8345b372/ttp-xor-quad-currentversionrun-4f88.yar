rule TTP_XOR_QUAD_CurrentVersionRun_4f88 {
  strings:
    $key_4f88 = { 1c e7 [2] 38 e9 [2] 13 c5 [2] 3d e7 [2] 29 fc [2] 26 e6 [2] 38 fb [2] 3a fa [2] 21 fc [2] 3d fb [2] 21 d4 }

  condition:
    any of them
}