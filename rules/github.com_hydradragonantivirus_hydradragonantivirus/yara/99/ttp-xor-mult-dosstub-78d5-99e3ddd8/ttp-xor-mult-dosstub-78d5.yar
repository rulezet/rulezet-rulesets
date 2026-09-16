rule TTP_XOR_MULT_DOSStub_78d5 {
  strings:
    $key_78d5 = { 2c bd [2] 58 a5 [2] 1f a7 [2] 58 b6 [2] 16 ba [2] 1a b0 [2] 0d bb [2] 16 f5 [2] 2b }

  condition:
    any of them
}