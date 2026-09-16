rule TTP_XOR_MULT_DOSStub_78f8 {
  strings:
    $key_78f8 = { 2c 90 [2] 58 88 [2] 1f 8a [2] 58 9b [2] 16 97 [2] 1a 9d [2] 0d 96 [2] 16 d8 [2] 2b }

  condition:
    any of them
}