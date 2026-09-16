rule TTP_XOR_MULT_DOSStub_d845 {
  strings:
    $key_d845 = { 8c 2d [2] f8 35 [2] bf 37 [2] f8 26 [2] b6 2a [2] ba 20 [2] ad 2b [2] b6 65 [2] 8b }

  condition:
    any of them
}