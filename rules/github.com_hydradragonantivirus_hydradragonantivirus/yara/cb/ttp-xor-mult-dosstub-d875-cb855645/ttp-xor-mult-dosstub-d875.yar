rule TTP_XOR_MULT_DOSStub_d875 {
  strings:
    $key_d875 = { 8c 1d [2] f8 05 [2] bf 07 [2] f8 16 [2] b6 1a [2] ba 10 [2] ad 1b [2] b6 55 [2] 8b }

  condition:
    any of them
}