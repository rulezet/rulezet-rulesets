rule TTP_XOR_QUAD_CurrentVersionRun_3d89 {
  strings:
    $key_3d89 = { 6e e6 [2] 4a e8 [2] 61 c4 [2] 4f e6 [2] 5b fd [2] 54 e7 [2] 4a fa [2] 48 fb [2] 53 fd [2] 4f fa [2] 53 d5 }

  condition:
    any of them
}