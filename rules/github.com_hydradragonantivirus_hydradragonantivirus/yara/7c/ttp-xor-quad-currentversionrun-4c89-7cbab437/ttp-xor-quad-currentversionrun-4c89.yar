rule TTP_XOR_QUAD_CurrentVersionRun_4c89 {
  strings:
    $key_4c89 = { 1f e6 [2] 3b e8 [2] 10 c4 [2] 3e e6 [2] 2a fd [2] 25 e7 [2] 3b fa [2] 39 fb [2] 22 fd [2] 3e fa [2] 22 d5 }

  condition:
    any of them
}