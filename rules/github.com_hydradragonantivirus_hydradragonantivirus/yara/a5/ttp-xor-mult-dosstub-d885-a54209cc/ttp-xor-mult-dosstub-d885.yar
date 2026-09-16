rule TTP_XOR_MULT_DOSStub_d885 {
  strings:
    $key_d885 = { 8c ed [2] f8 f5 [2] bf f7 [2] f8 e6 [2] b6 ea [2] ba e0 [2] ad eb [2] b6 a5 [2] 8b }

  condition:
    any of them
}