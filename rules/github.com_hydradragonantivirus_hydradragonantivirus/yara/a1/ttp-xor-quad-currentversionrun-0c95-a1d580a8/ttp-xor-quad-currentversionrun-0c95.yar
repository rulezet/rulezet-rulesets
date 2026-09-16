rule TTP_XOR_QUAD_CurrentVersionRun_0c95 {
  strings:
    $key_0c95 = { 5f fa [2] 7b f4 [2] 50 d8 [2] 7e fa [2] 6a e1 [2] 65 fb [2] 7b e6 [2] 79 e7 [2] 62 e1 [2] 7e e6 [2] 62 c9 }

  condition:
    any of them
}