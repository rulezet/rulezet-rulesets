rule TTP_XOR_MULT_DOSStub_5532 {
  strings:
    $key_5532 = { 01 5a [2] 75 42 [2] 32 40 [2] 75 51 [2] 3b 5d [2] 37 57 [2] 20 5c [2] 3b 12 [2] 06 }

  condition:
    any of them
}