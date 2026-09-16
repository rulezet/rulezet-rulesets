rule TTP_XOR_QUAD_CurrentVersionRun_5885 {
  strings:
    $key_5885 = { 0b ea [2] 2f e4 [2] 04 c8 [2] 2a ea [2] 3e f1 [2] 31 eb [2] 2f f6 [2] 2d f7 [2] 36 f1 [2] 2a f6 [2] 36 d9 }

  condition:
    any of them
}