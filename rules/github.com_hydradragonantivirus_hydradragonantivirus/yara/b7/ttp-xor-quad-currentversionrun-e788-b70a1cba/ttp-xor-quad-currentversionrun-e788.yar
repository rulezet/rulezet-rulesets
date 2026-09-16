rule TTP_XOR_QUAD_CurrentVersionRun_e788 {
  strings:
    $key_e788 = { b4 e7 [2] 90 e9 [2] bb c5 [2] 95 e7 [2] 81 fc [2] 8e e6 [2] 90 fb [2] 92 fa [2] 89 fc [2] 95 fb [2] 89 d4 }

  condition:
    any of them
}