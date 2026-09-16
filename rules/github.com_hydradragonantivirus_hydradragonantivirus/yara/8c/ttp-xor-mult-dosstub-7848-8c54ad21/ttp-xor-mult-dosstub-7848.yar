rule TTP_XOR_MULT_DOSStub_7848 {
  strings:
    $key_7848 = { 2c 20 [2] 58 38 [2] 1f 3a [2] 58 2b [2] 16 27 [2] 1a 2d [2] 0d 26 [2] 16 68 [2] 2b }

  condition:
    any of them
}