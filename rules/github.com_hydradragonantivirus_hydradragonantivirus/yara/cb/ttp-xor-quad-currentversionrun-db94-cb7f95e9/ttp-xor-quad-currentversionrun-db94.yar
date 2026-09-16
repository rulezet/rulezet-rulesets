rule TTP_XOR_QUAD_CurrentVersionRun_db94 {
  strings:
    $key_db94 = { 88 fb [2] ac f5 [2] 87 d9 [2] a9 fb [2] bd e0 [2] b2 fa [2] ac e7 [2] ae e6 [2] b5 e0 [2] a9 e7 [2] b5 c8 }

  condition:
    any of them
}