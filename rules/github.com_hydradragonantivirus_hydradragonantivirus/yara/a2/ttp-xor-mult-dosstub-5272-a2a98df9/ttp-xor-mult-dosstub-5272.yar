rule TTP_XOR_MULT_DOSStub_5272 {
  strings:
    $key_5272 = { 06 1a [2] 72 02 [2] 35 00 [2] 72 11 [2] 3c 1d [2] 30 17 [2] 27 1c [2] 3c 52 [2] 01 }

  condition:
    any of them
}