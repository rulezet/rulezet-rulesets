rule TTP_XOR_MULT_DOSStub_7859 {
  strings:
    $key_7859 = { 2c 31 [2] 58 29 [2] 1f 2b [2] 58 3a [2] 16 36 [2] 1a 3c [2] 0d 37 [2] 16 79 [2] 2b }

  condition:
    any of them
}