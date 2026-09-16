rule TTP_XOR_MULT_DOSStub_d8e4 {
  strings:
    $key_d8e4 = { 8c 8c [2] f8 94 [2] bf 96 [2] f8 87 [2] b6 8b [2] ba 81 [2] ad 8a [2] b6 c4 [2] 8b }

  condition:
    any of them
}