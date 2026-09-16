rule TTP_XOR_QUAD_CurrentVersionRun_7c95 {
  strings:
    $key_7c95 = { 2f fa [2] 0b f4 [2] 20 d8 [2] 0e fa [2] 1a e1 [2] 15 fb [2] 0b e6 [2] 09 e7 [2] 12 e1 [2] 0e e6 [2] 12 c9 }

  condition:
    any of them
}