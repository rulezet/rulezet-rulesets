rule TTP_XOR_MULT_DOSStub_d808 {
  strings:
    $key_d808 = { 8c 60 [2] f8 78 [2] bf 7a [2] f8 6b [2] b6 67 [2] ba 6d [2] ad 66 [2] b6 28 [2] 8b }

  condition:
    any of them
}