rule TTP_XOR_QUAD_CurrentVersionRun_f289 {
  strings:
    $key_f289 = { a1 e6 [2] 85 e8 [2] ae c4 [2] 80 e6 [2] 94 fd [2] 9b e7 [2] 85 fa [2] 87 fb [2] 9c fd [2] 80 fa [2] 9c d5 }

  condition:
    any of them
}