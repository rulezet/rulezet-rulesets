rule TTP_XOR_QUAD_CurrentVersionRun_dc94 {
  strings:
    $key_dc94 = { 8f fb [2] ab f5 [2] 80 d9 [2] ae fb [2] ba e0 [2] b5 fa [2] ab e7 [2] a9 e6 [2] b2 e0 [2] ae e7 [2] b2 c8 }

  condition:
    any of them
}