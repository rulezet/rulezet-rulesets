rule TTP_XOR_QUAD_CurrentVersionRun_6885 {
  strings:
    $key_6885 = { 3b ea [2] 1f e4 [2] 34 c8 [2] 1a ea [2] 0e f1 [2] 01 eb [2] 1f f6 [2] 1d f7 [2] 06 f1 [2] 1a f6 [2] 06 d9 }

  condition:
    any of them
}