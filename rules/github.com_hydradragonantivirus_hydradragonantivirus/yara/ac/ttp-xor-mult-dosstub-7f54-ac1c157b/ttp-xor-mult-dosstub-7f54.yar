rule TTP_XOR_MULT_DOSStub_7f54 {
  strings:
    $key_7f54 = { 2b 3c [2] 5f 24 [2] 18 26 [2] 5f 37 [2] 11 3b [2] 1d 31 [2] 0a 3a [2] 11 74 [2] 2c }

  condition:
    any of them
}