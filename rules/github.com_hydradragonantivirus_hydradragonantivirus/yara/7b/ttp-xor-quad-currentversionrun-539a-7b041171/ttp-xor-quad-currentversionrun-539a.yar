rule TTP_XOR_QUAD_CurrentVersionRun_539a {
  strings:
    $key_539a = { 00 f5 [2] 24 fb [2] 0f d7 [2] 21 f5 [2] 35 ee [2] 3a f4 [2] 24 e9 [2] 26 e8 [2] 3d ee [2] 21 e9 [2] 3d c6 }

  condition:
    any of them
}