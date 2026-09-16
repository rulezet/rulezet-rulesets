rule TTP_XOR_MULT_DOSStub_d820 {
  strings:
    $key_d820 = { 8c 48 [2] f8 50 [2] bf 52 [2] f8 43 [2] b6 4f [2] ba 45 [2] ad 4e [2] b6 00 [2] 8b }

  condition:
    any of them
}