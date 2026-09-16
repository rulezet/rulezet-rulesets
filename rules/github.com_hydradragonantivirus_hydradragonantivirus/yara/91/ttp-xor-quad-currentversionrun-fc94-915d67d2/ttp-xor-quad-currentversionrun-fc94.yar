rule TTP_XOR_QUAD_CurrentVersionRun_fc94 {
  strings:
    $key_fc94 = { af fb [2] 8b f5 [2] a0 d9 [2] 8e fb [2] 9a e0 [2] 95 fa [2] 8b e7 [2] 89 e6 [2] 92 e0 [2] 8e e7 [2] 92 c8 }

  condition:
    any of them
}