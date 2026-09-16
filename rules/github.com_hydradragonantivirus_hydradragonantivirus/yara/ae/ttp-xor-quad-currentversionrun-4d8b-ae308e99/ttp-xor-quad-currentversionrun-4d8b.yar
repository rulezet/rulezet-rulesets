rule TTP_XOR_QUAD_CurrentVersionRun_4d8b {
  strings:
    $key_4d8b = { 1e e4 [2] 3a ea [2] 11 c6 [2] 3f e4 [2] 2b ff [2] 24 e5 [2] 3a f8 [2] 38 f9 [2] 23 ff [2] 3f f8 [2] 23 d7 }

  condition:
    any of them
}