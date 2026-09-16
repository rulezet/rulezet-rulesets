rule TTP_XOR_QUAD_CurrentVersionRun_4d9a {
  strings:
    $key_4d9a = { 1e f5 [2] 3a fb [2] 11 d7 [2] 3f f5 [2] 2b ee [2] 24 f4 [2] 3a e9 [2] 38 e8 [2] 23 ee [2] 3f e9 [2] 23 c6 }

  condition:
    any of them
}