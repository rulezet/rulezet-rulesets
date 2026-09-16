rule TTP_XOR_MULT_DOSStub_d8e5 {
  strings:
    $key_d8e5 = { 8c 8d [2] f8 95 [2] bf 97 [2] f8 86 [2] b6 8a [2] ba 80 [2] ad 8b [2] b6 c5 [2] 8b }

  condition:
    any of them
}