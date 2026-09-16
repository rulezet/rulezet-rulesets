rule TTP_XOR_MULT_DOSStub_1532 {
  strings:
    $key_1532 = { 41 5a [2] 35 42 [2] 72 40 [2] 35 51 [2] 7b 5d [2] 77 57 [2] 60 5c [2] 7b 12 [2] 46 }

  condition:
    any of them
}