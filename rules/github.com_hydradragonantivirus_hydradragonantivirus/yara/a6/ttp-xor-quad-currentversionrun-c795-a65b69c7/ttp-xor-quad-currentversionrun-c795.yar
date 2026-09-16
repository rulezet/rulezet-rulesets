rule TTP_XOR_QUAD_CurrentVersionRun_c795 {
  strings:
    $key_c795 = { 94 fa [2] b0 f4 [2] 9b d8 [2] b5 fa [2] a1 e1 [2] ae fb [2] b0 e6 [2] b2 e7 [2] a9 e1 [2] b5 e6 [2] a9 c9 }

  condition:
    any of them
}