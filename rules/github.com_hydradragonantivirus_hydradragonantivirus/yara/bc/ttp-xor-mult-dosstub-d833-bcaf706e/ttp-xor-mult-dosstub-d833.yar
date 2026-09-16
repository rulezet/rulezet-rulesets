rule TTP_XOR_MULT_DOSStub_d833 {
  strings:
    $key_d833 = { 8c 5b [2] f8 43 [2] bf 41 [2] f8 50 [2] b6 5c [2] ba 56 [2] ad 5d [2] b6 13 [2] 8b }

  condition:
    any of them
}