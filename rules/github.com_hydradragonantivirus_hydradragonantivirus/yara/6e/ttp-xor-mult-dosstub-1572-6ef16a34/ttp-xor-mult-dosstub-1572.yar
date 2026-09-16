rule TTP_XOR_MULT_DOSStub_1572 {
  strings:
    $key_1572 = { 41 1a [2] 35 02 [2] 72 00 [2] 35 11 [2] 7b 1d [2] 77 17 [2] 60 1c [2] 7b 52 [2] 46 }

  condition:
    any of them
}