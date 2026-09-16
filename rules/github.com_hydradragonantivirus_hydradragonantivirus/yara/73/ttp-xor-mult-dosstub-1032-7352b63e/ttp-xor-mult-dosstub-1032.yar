rule TTP_XOR_MULT_DOSStub_1032 {
  strings:
    $key_1032 = { 44 5a [2] 30 42 [2] 77 40 [2] 30 51 [2] 7e 5d [2] 72 57 [2] 65 5c [2] 7e 12 [2] 43 }

  condition:
    any of them
}