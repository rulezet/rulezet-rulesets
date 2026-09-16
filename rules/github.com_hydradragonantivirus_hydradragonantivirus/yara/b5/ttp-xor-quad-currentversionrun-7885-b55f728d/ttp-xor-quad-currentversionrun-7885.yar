rule TTP_XOR_QUAD_CurrentVersionRun_7885 {
  strings:
    $key_7885 = { 2b ea [2] 0f e4 [2] 24 c8 [2] 0a ea [2] 1e f1 [2] 11 eb [2] 0f f6 [2] 0d f7 [2] 16 f1 [2] 0a f6 [2] 16 d9 }

  condition:
    any of them
}