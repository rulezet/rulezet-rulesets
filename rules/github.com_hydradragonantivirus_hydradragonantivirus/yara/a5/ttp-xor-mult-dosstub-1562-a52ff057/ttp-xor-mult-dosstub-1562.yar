rule TTP_XOR_MULT_DOSStub_1562 {
  strings:
    $key_1562 = { 41 0a [2] 35 12 [2] 72 10 [2] 35 01 [2] 7b 0d [2] 77 07 [2] 60 0c [2] 7b 42 [2] 46 }

  condition:
    any of them
}