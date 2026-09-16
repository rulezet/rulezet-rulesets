rule TTP_XOR_QUAD_CurrentVersionRun_d995 {
  strings:
    $key_d995 = { 8a fa [2] ae f4 [2] 85 d8 [2] ab fa [2] bf e1 [2] b0 fb [2] ae e6 [2] ac e7 [2] b7 e1 [2] ab e6 [2] b7 c9 }

  condition:
    any of them
}