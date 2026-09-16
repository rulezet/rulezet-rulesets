rule TTP_XOR_QUAD_CurrentVersionRun_6e9a {
  strings:
    $key_6e9a = { 3d f5 [2] 19 fb [2] 32 d7 [2] 1c f5 [2] 08 ee [2] 07 f4 [2] 19 e9 [2] 1b e8 [2] 00 ee [2] 1c e9 [2] 00 c6 }

  condition:
    any of them
}