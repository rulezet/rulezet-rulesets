rule TTP_XOR_MULT_DOSStub_d838 {
  strings:
    $key_d838 = { 8c 50 [2] f8 48 [2] bf 4a [2] f8 5b [2] b6 57 [2] ba 5d [2] ad 56 [2] b6 18 [2] 8b }

  condition:
    any of them
}