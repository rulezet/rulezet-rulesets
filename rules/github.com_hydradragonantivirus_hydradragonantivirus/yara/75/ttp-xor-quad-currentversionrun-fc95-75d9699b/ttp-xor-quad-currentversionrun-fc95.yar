rule TTP_XOR_QUAD_CurrentVersionRun_fc95 {
  strings:
    $key_fc95 = { af fa [2] 8b f4 [2] a0 d8 [2] 8e fa [2] 9a e1 [2] 95 fb [2] 8b e6 [2] 89 e7 [2] 92 e1 [2] 8e e6 [2] 92 c9 }

  condition:
    any of them
}