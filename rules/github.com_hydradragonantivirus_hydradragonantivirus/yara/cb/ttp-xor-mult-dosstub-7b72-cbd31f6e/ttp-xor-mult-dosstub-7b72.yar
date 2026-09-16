rule TTP_XOR_MULT_DOSStub_7b72 {
  strings:
    $key_7b72 = { 2f 1a [2] 5b 02 [2] 1c 00 [2] 5b 11 [2] 15 1d [2] 19 17 [2] 0e 1c [2] 15 52 [2] 28 }

  condition:
    any of them
}