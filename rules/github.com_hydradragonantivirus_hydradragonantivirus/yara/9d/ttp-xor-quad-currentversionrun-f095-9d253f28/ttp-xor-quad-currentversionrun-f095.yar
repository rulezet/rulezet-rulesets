rule TTP_XOR_QUAD_CurrentVersionRun_f095 {
  strings:
    $key_f095 = { a3 fa [2] 87 f4 [2] ac d8 [2] 82 fa [2] 96 e1 [2] 99 fb [2] 87 e6 [2] 85 e7 [2] 9e e1 [2] 82 e6 [2] 9e c9 }

  condition:
    any of them
}