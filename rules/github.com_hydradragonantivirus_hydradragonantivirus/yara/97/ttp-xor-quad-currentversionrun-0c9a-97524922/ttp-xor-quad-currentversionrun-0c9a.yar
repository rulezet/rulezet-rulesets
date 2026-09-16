rule TTP_XOR_QUAD_CurrentVersionRun_0c9a {
  strings:
    $key_0c9a = { 5f f5 [2] 7b fb [2] 50 d7 [2] 7e f5 [2] 6a ee [2] 65 f4 [2] 7b e9 [2] 79 e8 [2] 62 ee [2] 7e e9 [2] 62 c6 }

  condition:
    any of them
}