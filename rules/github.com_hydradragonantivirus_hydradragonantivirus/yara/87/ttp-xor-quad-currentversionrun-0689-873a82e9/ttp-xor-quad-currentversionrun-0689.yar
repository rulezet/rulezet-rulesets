rule TTP_XOR_QUAD_CurrentVersionRun_0689 {
  strings:
    $key_0689 = { 55 e6 [2] 71 e8 [2] 5a c4 [2] 74 e6 [2] 60 fd [2] 6f e7 [2] 71 fa [2] 73 fb [2] 68 fd [2] 74 fa [2] 68 d5 }

  condition:
    any of them
}