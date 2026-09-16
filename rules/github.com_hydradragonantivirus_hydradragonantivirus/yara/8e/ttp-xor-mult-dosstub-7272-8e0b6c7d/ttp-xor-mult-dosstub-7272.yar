rule TTP_XOR_MULT_DOSStub_7272 {
  strings:
    $key_7272 = { 26 1a [2] 52 02 [2] 15 00 [2] 52 11 [2] 1c 1d [2] 10 17 [2] 07 1c [2] 1c 52 [2] 21 }

  condition:
    any of them
}