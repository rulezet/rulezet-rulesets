rule TTP_XOR_MULT_DOSStub_d8f4 {
  strings:
    $key_d8f4 = { 8c 9c [2] f8 84 [2] bf 86 [2] f8 97 [2] b6 9b [2] ba 91 [2] ad 9a [2] b6 d4 [2] 8b }

  condition:
    any of them
}