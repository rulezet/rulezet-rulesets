rule TTP_XOR_MULT_DOSStub_b9b9 {
  strings:
    $key_b9b9 = { ed d1 [2] 99 c9 [2] de cb [2] 99 da [2] d7 d6 [2] db dc [2] cc d7 [2] d7 99 [2] ea }

  condition:
    any of them
}