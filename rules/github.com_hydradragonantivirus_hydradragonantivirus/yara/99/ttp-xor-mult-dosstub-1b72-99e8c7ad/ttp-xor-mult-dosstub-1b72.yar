rule TTP_XOR_MULT_DOSStub_1b72 {
  strings:
    $key_1b72 = { 4f 1a [2] 3b 02 [2] 7c 00 [2] 3b 11 [2] 75 1d [2] 79 17 [2] 6e 1c [2] 75 52 [2] 48 }

  condition:
    any of them
}