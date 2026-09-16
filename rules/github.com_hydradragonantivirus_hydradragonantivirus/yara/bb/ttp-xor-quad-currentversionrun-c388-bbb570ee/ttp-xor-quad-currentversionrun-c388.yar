rule TTP_XOR_QUAD_CurrentVersionRun_c388 {
  strings:
    $key_c388 = { 90 e7 [2] b4 e9 [2] 9f c5 [2] b1 e7 [2] a5 fc [2] aa e6 [2] b4 fb [2] b6 fa [2] ad fc [2] b1 fb [2] ad d4 }

  condition:
    any of them
}