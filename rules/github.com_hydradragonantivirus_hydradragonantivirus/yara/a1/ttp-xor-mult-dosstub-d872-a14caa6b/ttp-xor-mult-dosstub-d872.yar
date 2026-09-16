rule TTP_XOR_MULT_DOSStub_d872 {
  strings:
    $key_d872 = { 8c 1a [2] f8 02 [2] bf 00 [2] f8 11 [2] b6 1d [2] ba 17 [2] ad 1c [2] b6 52 [2] 8b }

  condition:
    any of them
}