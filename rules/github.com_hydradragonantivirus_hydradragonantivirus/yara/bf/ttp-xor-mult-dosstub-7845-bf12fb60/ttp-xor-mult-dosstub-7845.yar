rule TTP_XOR_MULT_DOSStub_7845 {
  strings:
    $key_7845 = { 2c 2d [2] 58 35 [2] 1f 37 [2] 58 26 [2] 16 2a [2] 1a 20 [2] 0d 2b [2] 16 65 [2] 2b }

  condition:
    any of them
}