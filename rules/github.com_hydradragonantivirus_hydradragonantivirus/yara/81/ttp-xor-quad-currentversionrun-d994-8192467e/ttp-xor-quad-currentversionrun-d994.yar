rule TTP_XOR_QUAD_CurrentVersionRun_d994 {
  strings:
    $key_d994 = { 8a fb [2] ae f5 [2] 85 d9 [2] ab fb [2] bf e0 [2] b0 fa [2] ae e7 [2] ac e6 [2] b7 e0 [2] ab e7 [2] b7 c8 }

  condition:
    any of them
}