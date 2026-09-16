rule TTP_XOR_MULT_DOSStub_4472 {
  strings:
    $key_4472 = { 10 1a [2] 64 02 [2] 23 00 [2] 64 11 [2] 2a 1d [2] 26 17 [2] 31 1c [2] 2a 52 [2] 17 }

  condition:
    any of them
}