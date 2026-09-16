rule TTP_XOR_QUAD_CurrentVersionRun_0688 {
  strings:
    $key_0688 = { 55 e7 [2] 71 e9 [2] 5a c5 [2] 74 e7 [2] 60 fc [2] 6f e6 [2] 71 fb [2] 73 fa [2] 68 fc [2] 74 fb [2] 68 d4 }

  condition:
    any of them
}