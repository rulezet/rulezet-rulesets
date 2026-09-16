rule TTP_XOR_MULT_DOSStub_6259 {
  strings:
    $key_6259 = { 36 31 [2] 42 29 [2] 05 2b [2] 42 3a [2] 0c 36 [2] 00 3c [2] 17 37 [2] 0c 79 [2] 31 }

  condition:
    any of them
}