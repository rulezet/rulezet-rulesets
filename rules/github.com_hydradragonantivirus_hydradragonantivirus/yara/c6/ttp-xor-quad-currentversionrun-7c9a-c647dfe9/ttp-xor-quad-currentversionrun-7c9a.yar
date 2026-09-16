rule TTP_XOR_QUAD_CurrentVersionRun_7c9a {
  strings:
    $key_7c9a = { 2f f5 [2] 0b fb [2] 20 d7 [2] 0e f5 [2] 1a ee [2] 15 f4 [2] 0b e9 [2] 09 e8 [2] 12 ee [2] 0e e9 [2] 12 c6 }

  condition:
    any of them
}