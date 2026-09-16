rule TTP_XOR_QUAD_CurrentVersionRun_0188 {
  strings:
    $key_0188 = { 52 e7 [2] 76 e9 [2] 5d c5 [2] 73 e7 [2] 67 fc [2] 68 e6 [2] 76 fb [2] 74 fa [2] 6f fc [2] 73 fb [2] 6f d4 }

  condition:
    any of them
}