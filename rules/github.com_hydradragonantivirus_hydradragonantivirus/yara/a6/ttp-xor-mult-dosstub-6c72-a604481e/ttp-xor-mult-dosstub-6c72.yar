rule TTP_XOR_MULT_DOSStub_6c72 {
  strings:
    $key_6c72 = { 38 1a [2] 4c 02 [2] 0b 00 [2] 4c 11 [2] 02 1d [2] 0e 17 [2] 19 1c [2] 02 52 [2] 3f }

  condition:
    any of them
}