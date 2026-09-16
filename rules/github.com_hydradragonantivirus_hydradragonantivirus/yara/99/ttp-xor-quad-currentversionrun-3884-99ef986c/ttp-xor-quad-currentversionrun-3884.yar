rule TTP_XOR_QUAD_CurrentVersionRun_3884 {
  strings:
    $key_3884 = { 6b eb [2] 4f e5 [2] 64 c9 [2] 4a eb [2] 5e f0 [2] 51 ea [2] 4f f7 [2] 4d f6 [2] 56 f0 [2] 4a f7 [2] 56 d8 }

  condition:
    any of them
}