rule TTP_XOR_MULT_DOSStub_d884 {
  strings:
    $key_d884 = { 8c ec [2] f8 f4 [2] bf f6 [2] f8 e7 [2] b6 eb [2] ba e1 [2] ad ea [2] b6 a4 [2] 8b }

  condition:
    any of them
}