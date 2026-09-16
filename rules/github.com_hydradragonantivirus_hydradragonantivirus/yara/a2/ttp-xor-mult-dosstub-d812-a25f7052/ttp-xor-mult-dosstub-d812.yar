rule TTP_XOR_MULT_DOSStub_d812 {
  strings:
    $key_d812 = { 8c 7a [2] f8 62 [2] bf 60 [2] f8 71 [2] b6 7d [2] ba 77 [2] ad 7c [2] b6 32 [2] 8b }

  condition:
    any of them
}