rule TTP_XOR_QUAD_CurrentVersionRun_3d8b {
  strings:
    $key_3d8b = { 6e e4 [2] 4a ea [2] 61 c6 [2] 4f e4 [2] 5b ff [2] 54 e5 [2] 4a f8 [2] 48 f9 [2] 53 ff [2] 4f f8 [2] 53 d7 }

  condition:
    any of them
}