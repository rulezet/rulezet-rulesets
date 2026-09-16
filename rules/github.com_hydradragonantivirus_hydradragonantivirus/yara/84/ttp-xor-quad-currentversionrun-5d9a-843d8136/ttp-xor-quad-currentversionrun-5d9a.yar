rule TTP_XOR_QUAD_CurrentVersionRun_5d9a {
  strings:
    $key_5d9a = { 0e f5 [2] 2a fb [2] 01 d7 [2] 2f f5 [2] 3b ee [2] 34 f4 [2] 2a e9 [2] 28 e8 [2] 33 ee [2] 2f e9 [2] 33 c6 }

  condition:
    any of them
}