rule TTP_XOR_MULT_DOSStub_7884 {
  strings:
    $key_7884 = { 2c ec [2] 58 f4 [2] 1f f6 [2] 58 e7 [2] 16 eb [2] 1a e1 [2] 0d ea [2] 16 a4 [2] 2b }

  condition:
    any of them
}