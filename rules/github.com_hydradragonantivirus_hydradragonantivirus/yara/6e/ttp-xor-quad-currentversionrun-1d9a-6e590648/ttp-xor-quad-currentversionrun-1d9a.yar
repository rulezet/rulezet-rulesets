rule TTP_XOR_QUAD_CurrentVersionRun_1d9a {
  strings:
    $key_1d9a = { 4e f5 [2] 6a fb [2] 41 d7 [2] 6f f5 [2] 7b ee [2] 74 f4 [2] 6a e9 [2] 68 e8 [2] 73 ee [2] 6f e9 [2] 73 c6 }

  condition:
    any of them
}