rule TTP_XOR_QUAD_CurrentVersionRun_db95 {
  strings:
    $key_db95 = { 88 fa [2] ac f4 [2] 87 d8 [2] a9 fa [2] bd e1 [2] b2 fb [2] ac e6 [2] ae e7 [2] b5 e1 [2] a9 e6 [2] b5 c9 }

  condition:
    any of them
}