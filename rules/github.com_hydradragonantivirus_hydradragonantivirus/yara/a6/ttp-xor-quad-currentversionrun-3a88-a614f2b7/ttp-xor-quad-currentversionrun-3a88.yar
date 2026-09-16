rule TTP_XOR_QUAD_CurrentVersionRun_3a88 {
  strings:
    $key_3a88 = { 69 e7 [2] 4d e9 [2] 66 c5 [2] 48 e7 [2] 5c fc [2] 53 e6 [2] 4d fb [2] 4f fa [2] 54 fc [2] 48 fb [2] 54 d4 }

  condition:
    any of them
}