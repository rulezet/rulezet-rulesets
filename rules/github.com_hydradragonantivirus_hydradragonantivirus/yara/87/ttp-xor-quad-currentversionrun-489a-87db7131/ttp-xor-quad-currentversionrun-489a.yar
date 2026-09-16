rule TTP_XOR_QUAD_CurrentVersionRun_489a {
  strings:
    $key_489a = { 1b f5 [2] 3f fb [2] 14 d7 [2] 3a f5 [2] 2e ee [2] 21 f4 [2] 3f e9 [2] 3d e8 [2] 26 ee [2] 3a e9 [2] 26 c6 }

  condition:
    any of them
}