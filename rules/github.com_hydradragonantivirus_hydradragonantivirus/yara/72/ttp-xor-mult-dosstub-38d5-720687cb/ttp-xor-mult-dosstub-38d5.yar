rule TTP_XOR_MULT_DOSStub_38d5 {
  strings:
    $key_38d5 = { 6c bd [2] 18 a5 [2] 5f a7 [2] 18 b6 [2] 56 ba [2] 5a b0 [2] 4d bb [2] 56 f5 [2] 6b }

  condition:
    any of them
}