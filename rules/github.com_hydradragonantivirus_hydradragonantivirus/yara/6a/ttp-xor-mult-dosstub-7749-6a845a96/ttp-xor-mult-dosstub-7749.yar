rule TTP_XOR_MULT_DOSStub_7749 {
  strings:
    $key_7749 = { 23 21 [2] 57 39 [2] 10 3b [2] 57 2a [2] 19 26 [2] 15 2c [2] 02 27 [2] 19 69 [2] 24 }

  condition:
    any of them
}