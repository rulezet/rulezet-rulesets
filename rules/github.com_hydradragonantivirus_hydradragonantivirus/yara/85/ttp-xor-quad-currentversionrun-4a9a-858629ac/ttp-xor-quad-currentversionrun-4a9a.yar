rule TTP_XOR_QUAD_CurrentVersionRun_4a9a {
  strings:
    $key_4a9a = { 19 f5 [2] 3d fb [2] 16 d7 [2] 38 f5 [2] 2c ee [2] 23 f4 [2] 3d e9 [2] 3f e8 [2] 24 ee [2] 38 e9 [2] 24 c6 }

  condition:
    any of them
}