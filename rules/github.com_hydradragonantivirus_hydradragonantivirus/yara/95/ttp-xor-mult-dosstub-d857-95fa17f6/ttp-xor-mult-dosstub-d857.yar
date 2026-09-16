rule TTP_XOR_MULT_DOSStub_d857 {
  strings:
    $key_d857 = { 8c 3f [2] f8 27 [2] bf 25 [2] f8 34 [2] b6 38 [2] ba 32 [2] ad 39 [2] b6 77 [2] 8b }

  condition:
    any of them
}