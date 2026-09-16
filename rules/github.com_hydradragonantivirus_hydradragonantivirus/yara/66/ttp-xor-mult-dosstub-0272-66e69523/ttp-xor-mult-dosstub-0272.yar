rule TTP_XOR_MULT_DOSStub_0272 {
  strings:
    $key_0272 = { 56 1a [2] 22 02 [2] 65 00 [2] 22 11 [2] 6c 1d [2] 60 17 [2] 77 1c [2] 6c 52 [2] 51 }

  condition:
    any of them
}