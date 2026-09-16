rule TTP_XOR_MULT_DOSStub_d81a {
  strings:
    $key_d81a = { 8c 72 [2] f8 6a [2] bf 68 [2] f8 79 [2] b6 75 [2] ba 7f [2] ad 74 [2] b6 3a [2] 8b }

  condition:
    any of them
}