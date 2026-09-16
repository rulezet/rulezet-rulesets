rule TTP_XOR_QUAD_CurrentVersionRun_2d9a {
  strings:
    $key_2d9a = { 7e f5 [2] 5a fb [2] 71 d7 [2] 5f f5 [2] 4b ee [2] 44 f4 [2] 5a e9 [2] 58 e8 [2] 43 ee [2] 5f e9 [2] 43 c6 }

  condition:
    any of them
}