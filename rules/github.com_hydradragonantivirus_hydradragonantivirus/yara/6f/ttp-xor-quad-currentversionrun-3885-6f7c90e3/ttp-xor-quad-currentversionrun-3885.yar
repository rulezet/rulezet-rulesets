rule TTP_XOR_QUAD_CurrentVersionRun_3885 {
  strings:
    $key_3885 = { 6b ea [2] 4f e4 [2] 64 c8 [2] 4a ea [2] 5e f1 [2] 51 eb [2] 4f f6 [2] 4d f7 [2] 56 f1 [2] 4a f6 [2] 56 d9 }

  condition:
    any of them
}