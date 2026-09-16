rule TTP_XOR_QUAD_CurrentVersionRun_2a88 {
  strings:
    $key_2a88 = { 79 e7 [2] 5d e9 [2] 76 c5 [2] 58 e7 [2] 4c fc [2] 43 e6 [2] 5d fb [2] 5f fa [2] 44 fc [2] 58 fb [2] 44 d4 }

  condition:
    any of them
}