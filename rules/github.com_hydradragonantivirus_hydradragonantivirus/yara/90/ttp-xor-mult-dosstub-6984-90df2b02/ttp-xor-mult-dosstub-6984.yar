rule TTP_XOR_MULT_DOSStub_6984 {
  strings:
    $key_6984 = { 3d ec [2] 49 f4 [2] 0e f6 [2] 49 e7 [2] 07 eb [2] 0b e1 [2] 1c ea [2] 07 a4 [2] 3a }

  condition:
    any of them
}