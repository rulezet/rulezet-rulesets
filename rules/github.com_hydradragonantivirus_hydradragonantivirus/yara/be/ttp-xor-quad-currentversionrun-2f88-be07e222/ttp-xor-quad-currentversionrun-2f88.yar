rule TTP_XOR_QUAD_CurrentVersionRun_2f88 {
  strings:
    $key_2f88 = { 7c e7 [2] 58 e9 [2] 73 c5 [2] 5d e7 [2] 49 fc [2] 46 e6 [2] 58 fb [2] 5a fa [2] 41 fc [2] 5d fb [2] 41 d4 }

  condition:
    any of them
}