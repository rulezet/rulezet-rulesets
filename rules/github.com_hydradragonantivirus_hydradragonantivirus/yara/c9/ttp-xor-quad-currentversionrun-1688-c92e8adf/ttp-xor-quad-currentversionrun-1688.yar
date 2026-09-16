rule TTP_XOR_QUAD_CurrentVersionRun_1688 {
  strings:
    $key_1688 = { 45 e7 [2] 61 e9 [2] 4a c5 [2] 64 e7 [2] 70 fc [2] 7f e6 [2] 61 fb [2] 63 fa [2] 78 fc [2] 64 fb [2] 78 d4 }

  condition:
    any of them
}