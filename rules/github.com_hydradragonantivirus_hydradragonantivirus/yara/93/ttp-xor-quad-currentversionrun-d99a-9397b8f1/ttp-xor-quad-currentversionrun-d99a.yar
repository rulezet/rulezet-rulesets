rule TTP_XOR_QUAD_CurrentVersionRun_d99a {
  strings:
    $key_d99a = { 8a f5 [2] ae fb [2] 85 d7 [2] ab f5 [2] bf ee [2] b0 f4 [2] ae e9 [2] ac e8 [2] b7 ee [2] ab e9 [2] b7 c6 }

  condition:
    any of them
}