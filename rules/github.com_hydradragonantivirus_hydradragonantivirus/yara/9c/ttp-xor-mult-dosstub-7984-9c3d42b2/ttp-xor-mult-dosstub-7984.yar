rule TTP_XOR_MULT_DOSStub_7984 {
  strings:
    $key_7984 = { 2d ec [2] 59 f4 [2] 1e f6 [2] 59 e7 [2] 17 eb [2] 1b e1 [2] 0c ea [2] 17 a4 [2] 2a }

  condition:
    any of them
}