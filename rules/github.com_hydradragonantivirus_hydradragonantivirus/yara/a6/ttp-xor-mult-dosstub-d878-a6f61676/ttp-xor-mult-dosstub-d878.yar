rule TTP_XOR_MULT_DOSStub_d878 {
  strings:
    $key_d878 = { 8c 10 [2] f8 08 [2] bf 0a [2] f8 1b [2] b6 17 [2] ba 1d [2] ad 16 [2] b6 58 [2] 8b }

  condition:
    any of them
}