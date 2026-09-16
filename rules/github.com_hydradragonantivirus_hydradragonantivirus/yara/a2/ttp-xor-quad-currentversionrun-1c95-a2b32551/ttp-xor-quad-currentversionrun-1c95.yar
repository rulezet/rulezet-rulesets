rule TTP_XOR_QUAD_CurrentVersionRun_1c95 {
  strings:
    $key_1c95 = { 4f fa [2] 6b f4 [2] 40 d8 [2] 6e fa [2] 7a e1 [2] 75 fb [2] 6b e6 [2] 69 e7 [2] 72 e1 [2] 6e e6 [2] 72 c9 }

  condition:
    any of them
}