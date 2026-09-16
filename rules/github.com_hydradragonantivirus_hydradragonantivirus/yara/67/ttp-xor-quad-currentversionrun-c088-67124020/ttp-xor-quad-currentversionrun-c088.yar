rule TTP_XOR_QUAD_CurrentVersionRun_c088 {
  strings:
    $key_c088 = { 93 e7 [2] b7 e9 [2] 9c c5 [2] b2 e7 [2] a6 fc [2] a9 e6 [2] b7 fb [2] b5 fa [2] ae fc [2] b2 fb [2] ae d4 }

  condition:
    any of them
}