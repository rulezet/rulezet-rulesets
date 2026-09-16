rule TTP_XOR_MULT_DOSStub_d862 {
  strings:
    $key_d862 = { 8c 0a [2] f8 12 [2] bf 10 [2] f8 01 [2] b6 0d [2] ba 07 [2] ad 0c [2] b6 42 [2] 8b }

  condition:
    any of them
}