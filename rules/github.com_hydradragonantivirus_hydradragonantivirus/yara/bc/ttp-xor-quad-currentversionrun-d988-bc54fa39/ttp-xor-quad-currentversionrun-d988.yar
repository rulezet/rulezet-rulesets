rule TTP_XOR_QUAD_CurrentVersionRun_d988 {
  strings:
    $key_d988 = { 8a e7 [2] ae e9 [2] 85 c5 [2] ab e7 [2] bf fc [2] b0 e6 [2] ae fb [2] ac fa [2] b7 fc [2] ab fb [2] b7 d4 }

  condition:
    any of them
}