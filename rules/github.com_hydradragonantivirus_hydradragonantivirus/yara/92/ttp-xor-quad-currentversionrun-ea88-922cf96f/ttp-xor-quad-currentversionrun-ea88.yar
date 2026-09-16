rule TTP_XOR_QUAD_CurrentVersionRun_ea88 {
  strings:
    $key_ea88 = { b9 e7 [2] 9d e9 [2] b6 c5 [2] 98 e7 [2] 8c fc [2] 83 e6 [2] 9d fb [2] 9f fa [2] 84 fc [2] 98 fb [2] 84 d4 }

  condition:
    any of them
}