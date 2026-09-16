rule TTP_XOR_QUAD_CurrentVersionRun_1885 {
  strings:
    $key_1885 = { 4b ea [2] 6f e4 [2] 44 c8 [2] 6a ea [2] 7e f1 [2] 71 eb [2] 6f f6 [2] 6d f7 [2] 76 f1 [2] 6a f6 [2] 76 d9 }

  condition:
    any of them
}