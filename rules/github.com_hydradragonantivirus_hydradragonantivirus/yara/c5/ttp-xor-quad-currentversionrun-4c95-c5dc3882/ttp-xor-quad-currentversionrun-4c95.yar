rule TTP_XOR_QUAD_CurrentVersionRun_4c95 {
  strings:
    $key_4c95 = { 1f fa [2] 3b f4 [2] 10 d8 [2] 3e fa [2] 2a e1 [2] 25 fb [2] 3b e6 [2] 39 e7 [2] 22 e1 [2] 3e e6 [2] 22 c9 }

  condition:
    any of them
}