rule TTP_XOR_MULT_DOSStub_d489 {
  strings:
    $key_d489 = { 80 e1 [2] f4 f9 [2] b3 fb [2] f4 ea [2] ba e6 [2] b6 ec [2] a1 e7 [2] ba a9 [2] 87 }

  condition:
    any of them
}