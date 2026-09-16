rule TTP_XOR_QUAD_CurrentVersionRun_0995 {
  strings:
    $key_0995 = { 5a fa [2] 7e f4 [2] 55 d8 [2] 7b fa [2] 6f e1 [2] 60 fb [2] 7e e6 [2] 7c e7 [2] 67 e1 [2] 7b e6 [2] 67 c9 }

  condition:
    any of them
}