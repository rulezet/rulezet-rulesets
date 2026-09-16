rule TTP_XOR_MULT_DOSStub_d8f2 {
  strings:
    $key_d8f2 = { 8c 9a [2] f8 82 [2] bf 80 [2] f8 91 [2] b6 9d [2] ba 97 [2] ad 9c [2] b6 d2 [2] 8b }

  condition:
    any of them
}