rule TTP_XOR_MULT_DOSStub_7432 {
  strings:
    $key_7432 = { 20 5a [2] 54 42 [2] 13 40 [2] 54 51 [2] 1a 5d [2] 16 57 [2] 01 5c [2] 1a 12 [2] 27 }

  condition:
    any of them
}