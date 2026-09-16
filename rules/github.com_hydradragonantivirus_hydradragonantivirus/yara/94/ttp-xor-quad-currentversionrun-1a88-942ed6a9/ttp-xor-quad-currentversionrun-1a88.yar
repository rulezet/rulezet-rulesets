rule TTP_XOR_QUAD_CurrentVersionRun_1a88 {
  strings:
    $key_1a88 = { 49 e7 [2] 6d e9 [2] 46 c5 [2] 68 e7 [2] 7c fc [2] 73 e6 [2] 6d fb [2] 6f fa [2] 74 fc [2] 68 fb [2] 74 d4 }

  condition:
    any of them
}