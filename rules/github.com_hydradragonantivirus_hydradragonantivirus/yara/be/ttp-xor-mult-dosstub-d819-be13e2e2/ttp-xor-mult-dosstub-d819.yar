rule TTP_XOR_MULT_DOSStub_d819 {
  strings:
    $key_d819 = { 8c 71 [2] f8 69 [2] bf 6b [2] f8 7a [2] b6 76 [2] ba 7c [2] ad 77 [2] b6 39 [2] 8b }

  condition:
    any of them
}