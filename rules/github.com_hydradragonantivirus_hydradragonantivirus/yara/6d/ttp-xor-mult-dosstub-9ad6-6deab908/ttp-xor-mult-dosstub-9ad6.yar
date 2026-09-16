rule TTP_XOR_MULT_DOSStub_9ad6 {
  strings:
    $key_9ad6 = { ce be [2] ba a6 [2] fd a4 [2] ba b5 [2] f4 b9 [2] f8 b3 [2] ef b8 [2] f4 f6 [2] c9 }

  condition:
    any of them
}