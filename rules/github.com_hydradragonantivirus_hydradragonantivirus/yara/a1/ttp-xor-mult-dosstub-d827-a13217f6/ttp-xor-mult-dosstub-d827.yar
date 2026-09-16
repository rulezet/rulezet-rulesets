rule TTP_XOR_MULT_DOSStub_d827 {
  strings:
    $key_d827 = { 8c 4f [2] f8 57 [2] bf 55 [2] f8 44 [2] b6 48 [2] ba 42 [2] ad 49 [2] b6 07 [2] 8b }

  condition:
    any of them
}