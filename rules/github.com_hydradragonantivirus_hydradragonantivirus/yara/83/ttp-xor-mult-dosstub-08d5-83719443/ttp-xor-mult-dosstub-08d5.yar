rule TTP_XOR_MULT_DOSStub_08d5 {
  strings:
    $key_08d5 = { 5c bd [2] 28 a5 [2] 6f a7 [2] 28 b6 [2] 66 ba [2] 6a b0 [2] 7d bb [2] 66 f5 [2] 5b }

  condition:
    any of them
}