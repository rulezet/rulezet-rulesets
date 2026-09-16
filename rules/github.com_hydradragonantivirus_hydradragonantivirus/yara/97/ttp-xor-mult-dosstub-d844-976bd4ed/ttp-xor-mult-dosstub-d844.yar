rule TTP_XOR_MULT_DOSStub_d844 {
  strings:
    $key_d844 = { 8c 2c [2] f8 34 [2] bf 36 [2] f8 27 [2] b6 2b [2] ba 21 [2] ad 2a [2] b6 64 [2] 8b }

  condition:
    any of them
}