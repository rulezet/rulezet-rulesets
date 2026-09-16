rule TTP_XOR_MULT_DOSStub_4b72 {
  strings:
    $key_4b72 = { 1f 1a [2] 6b 02 [2] 2c 00 [2] 6b 11 [2] 25 1d [2] 29 17 [2] 3e 1c [2] 25 52 [2] 18 }

  condition:
    any of them
}