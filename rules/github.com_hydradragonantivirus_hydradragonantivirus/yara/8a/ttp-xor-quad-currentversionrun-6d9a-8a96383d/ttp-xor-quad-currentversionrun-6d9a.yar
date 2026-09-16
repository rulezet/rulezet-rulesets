rule TTP_XOR_QUAD_CurrentVersionRun_6d9a {
  strings:
    $key_6d9a = { 3e f5 [2] 1a fb [2] 31 d7 [2] 1f f5 [2] 0b ee [2] 04 f4 [2] 1a e9 [2] 18 e8 [2] 03 ee [2] 1f e9 [2] 03 c6 }

  condition:
    any of them
}