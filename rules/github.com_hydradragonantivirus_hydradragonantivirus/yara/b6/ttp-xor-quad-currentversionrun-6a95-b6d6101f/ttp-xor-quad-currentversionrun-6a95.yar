rule TTP_XOR_QUAD_CurrentVersionRun_6a95 {
  strings:
    $key_6a95 = { 39 fa [2] 1d f4 [2] 36 d8 [2] 18 fa [2] 0c e1 [2] 03 fb [2] 1d e6 [2] 1f e7 [2] 04 e1 [2] 18 e6 [2] 04 c9 }

  condition:
    any of them
}