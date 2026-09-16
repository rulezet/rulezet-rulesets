rule TTP_XOR_QUAD_CurrentVersionRun_7d9a {
  strings:
    $key_7d9a = { 2e f5 [2] 0a fb [2] 21 d7 [2] 0f f5 [2] 1b ee [2] 14 f4 [2] 0a e9 [2] 08 e8 [2] 13 ee [2] 0f e9 [2] 13 c6 }

  condition:
    any of them
}