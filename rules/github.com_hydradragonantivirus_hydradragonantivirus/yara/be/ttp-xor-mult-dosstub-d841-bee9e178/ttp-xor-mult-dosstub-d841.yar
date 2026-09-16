rule TTP_XOR_MULT_DOSStub_d841 {
  strings:
    $key_d841 = { 8c 29 [2] f8 31 [2] bf 33 [2] f8 22 [2] b6 2e [2] ba 24 [2] ad 2f [2] b6 61 [2] 8b }

  condition:
    any of them
}