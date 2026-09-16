rule TTP_XOR_QUAD_CurrentVersionRun_ed89 {
  strings:
    $key_ed89 = { be e6 [2] 9a e8 [2] b1 c4 [2] 9f e6 [2] 8b fd [2] 84 e7 [2] 9a fa [2] 98 fb [2] 83 fd [2] 9f fa [2] 83 d5 }

  condition:
    any of them
}