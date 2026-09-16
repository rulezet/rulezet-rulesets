rule TTP_XOR_QUAD_CurrentVersionRun_4c9a {
  strings:
    $key_4c9a = { 1f f5 [2] 3b fb [2] 10 d7 [2] 3e f5 [2] 2a ee [2] 25 f4 [2] 3b e9 [2] 39 e8 [2] 22 ee [2] 3e e9 [2] 22 c6 }

  condition:
    any of them
}