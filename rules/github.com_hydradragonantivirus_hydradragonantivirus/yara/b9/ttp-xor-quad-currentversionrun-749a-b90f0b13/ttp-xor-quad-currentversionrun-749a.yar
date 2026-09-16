rule TTP_XOR_QUAD_CurrentVersionRun_749a {
  strings:
    $key_749a = { 27 f5 [2] 03 fb [2] 28 d7 [2] 06 f5 [2] 12 ee [2] 1d f4 [2] 03 e9 [2] 01 e8 [2] 1a ee [2] 06 e9 [2] 1a c6 }

  condition:
    any of them
}