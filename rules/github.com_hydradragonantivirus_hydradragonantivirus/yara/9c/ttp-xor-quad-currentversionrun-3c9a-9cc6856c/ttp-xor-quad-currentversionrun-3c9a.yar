rule TTP_XOR_QUAD_CurrentVersionRun_3c9a {
  strings:
    $key_3c9a = { 6f f5 [2] 4b fb [2] 60 d7 [2] 4e f5 [2] 5a ee [2] 55 f4 [2] 4b e9 [2] 49 e8 [2] 52 ee [2] 4e e9 [2] 52 c6 }

  condition:
    any of them
}