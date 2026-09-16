rule TTP_XOR_MULT_DOSStub_d8e1 {
  strings:
    $key_d8e1 = { 8c 89 [2] f8 91 [2] bf 93 [2] f8 82 [2] b6 8e [2] ba 84 [2] ad 8f [2] b6 c1 [2] 8b }

  condition:
    any of them
}