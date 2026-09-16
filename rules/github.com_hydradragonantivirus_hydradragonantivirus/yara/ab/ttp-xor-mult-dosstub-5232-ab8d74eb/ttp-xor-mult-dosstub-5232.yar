rule TTP_XOR_MULT_DOSStub_5232 {
  strings:
    $key_5232 = { 06 5a [2] 72 42 [2] 35 40 [2] 72 51 [2] 3c 5d [2] 30 57 [2] 27 5c [2] 3c 12 [2] 01 }

  condition:
    any of them
}