rule TTP_XOR_MULT_DOSStub_d821 {
  strings:
    $key_d821 = { 8c 49 [2] f8 51 [2] bf 53 [2] f8 42 [2] b6 4e [2] ba 44 [2] ad 4f [2] b6 01 [2] 8b }

  condition:
    any of them
}