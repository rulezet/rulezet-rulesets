rule TTP_XOR_MULT_DOSStub_0984 {
  strings:
    $key_0984 = { 5d ec [2] 29 f4 [2] 6e f6 [2] 29 e7 [2] 67 eb [2] 6b e1 [2] 7c ea [2] 67 a4 [2] 5a }

  condition:
    any of them
}