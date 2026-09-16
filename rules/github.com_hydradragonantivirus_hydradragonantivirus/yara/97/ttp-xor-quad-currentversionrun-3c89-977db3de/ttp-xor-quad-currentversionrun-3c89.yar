rule TTP_XOR_QUAD_CurrentVersionRun_3c89 {
  strings:
    $key_3c89 = { 6f e6 [2] 4b e8 [2] 60 c4 [2] 4e e6 [2] 5a fd [2] 55 e7 [2] 4b fa [2] 49 fb [2] 52 fd [2] 4e fa [2] 52 d5 }

  condition:
    any of them
}