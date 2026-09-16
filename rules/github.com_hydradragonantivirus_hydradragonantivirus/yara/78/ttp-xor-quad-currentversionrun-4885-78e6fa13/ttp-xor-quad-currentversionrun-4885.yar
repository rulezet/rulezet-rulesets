rule TTP_XOR_QUAD_CurrentVersionRun_4885 {
  strings:
    $key_4885 = { 1b ea [2] 3f e4 [2] 14 c8 [2] 3a ea [2] 2e f1 [2] 21 eb [2] 3f f6 [2] 3d f7 [2] 26 f1 [2] 3a f6 [2] 26 d9 }

  condition:
    any of them
}