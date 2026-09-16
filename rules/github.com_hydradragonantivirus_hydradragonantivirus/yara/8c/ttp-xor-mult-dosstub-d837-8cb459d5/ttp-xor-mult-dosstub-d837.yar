rule TTP_XOR_MULT_DOSStub_d837 {
  strings:
    $key_d837 = { 8c 5f [2] f8 47 [2] bf 45 [2] f8 54 [2] b6 58 [2] ba 52 [2] ad 59 [2] b6 17 [2] 8b }

  condition:
    any of them
}