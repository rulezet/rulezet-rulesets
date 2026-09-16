rule TTP_XOR_QUAD_CurrentVersionRun_5d99 {
  strings:
    $key_5d99 = { 0e f6 [2] 2a f8 [2] 01 d4 [2] 2f f6 [2] 3b ed [2] 34 f7 [2] 2a ea [2] 28 eb [2] 33 ed [2] 2f ea [2] 33 c5 }

  condition:
    any of them
}