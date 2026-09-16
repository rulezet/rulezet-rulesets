rule TTP_XOR_MULT_DOSStub_5972 {
  strings:
    $key_5972 = { 0d 1a [2] 79 02 [2] 3e 00 [2] 79 11 [2] 37 1d [2] 3b 17 [2] 2c 1c [2] 37 52 [2] 0a }

  condition:
    any of them
}