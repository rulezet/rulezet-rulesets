rule TTP_XOR_MULT_DOSStub_1732 {
  strings:
    $key_1732 = { 43 5a [2] 37 42 [2] 70 40 [2] 37 51 [2] 79 5d [2] 75 57 [2] 62 5c [2] 79 12 [2] 44 }

  condition:
    any of them
}