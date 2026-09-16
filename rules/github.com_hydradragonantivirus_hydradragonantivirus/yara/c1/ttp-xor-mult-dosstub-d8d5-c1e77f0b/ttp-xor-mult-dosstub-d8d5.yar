rule TTP_XOR_MULT_DOSStub_d8d5 {
  strings:
    $key_d8d5 = { 8c bd [2] f8 a5 [2] bf a7 [2] f8 b6 [2] b6 ba [2] ba b0 [2] ad bb [2] b6 f5 [2] 8b }

  condition:
    any of them
}