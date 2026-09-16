rule TTP_XOR_MULT_DOSStub_d83f {
  strings:
    $key_d83f = { 8c 57 [2] f8 4f [2] bf 4d [2] f8 5c [2] b6 50 [2] ba 5a [2] ad 51 [2] b6 1f [2] 8b }

  condition:
    any of them
}