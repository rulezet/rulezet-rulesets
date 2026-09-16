rule TTP_XOR_QUAD_CurrentVersionRun_6c9a {
  strings:
    $key_6c9a = { 3f f5 [2] 1b fb [2] 30 d7 [2] 1e f5 [2] 0a ee [2] 05 f4 [2] 1b e9 [2] 19 e8 [2] 02 ee [2] 1e e9 [2] 02 c6 }

  condition:
    any of them
}