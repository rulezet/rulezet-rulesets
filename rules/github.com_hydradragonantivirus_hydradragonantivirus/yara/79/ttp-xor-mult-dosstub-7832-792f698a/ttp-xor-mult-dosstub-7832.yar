rule TTP_XOR_MULT_DOSStub_7832 {
  strings:
    $key_7832 = { 2c 5a [2] 58 42 [2] 1f 40 [2] 58 51 [2] 16 5d [2] 1a 57 [2] 0d 5c [2] 16 12 [2] 2b }

  condition:
    any of them
}