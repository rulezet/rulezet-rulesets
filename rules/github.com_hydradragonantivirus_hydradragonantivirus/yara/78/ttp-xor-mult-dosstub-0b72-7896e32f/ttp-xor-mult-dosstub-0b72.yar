rule TTP_XOR_MULT_DOSStub_0b72 {
  strings:
    $key_0b72 = { 5f 1a [2] 2b 02 [2] 6c 00 [2] 2b 11 [2] 65 1d [2] 69 17 [2] 7e 1c [2] 65 52 [2] 58 }

  condition:
    any of them
}