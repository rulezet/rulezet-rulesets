rule TTP_XOR_MULT_DOSStub_d840 {
  strings:
    $key_d840 = { 8c 28 [2] f8 30 [2] bf 32 [2] f8 23 [2] b6 2f [2] ba 25 [2] ad 2e [2] b6 60 [2] 8b }

  condition:
    any of them
}