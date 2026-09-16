rule TTP_XOR_MULT_DOSStub_d850 {
  strings:
    $key_d850 = { 8c 38 [2] f8 20 [2] bf 22 [2] f8 33 [2] b6 3f [2] ba 35 [2] ad 3e [2] b6 70 [2] 8b }

  condition:
    any of them
}