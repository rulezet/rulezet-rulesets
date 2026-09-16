rule TTP_XOR_MULT_DOSStub_1044 {
  strings:
    $key_1044 = { 44 2c [2] 30 34 [2] 77 36 [2] 30 27 [2] 7e 2b [2] 72 21 [2] 65 2a [2] 7e 64 [2] 43 }

  condition:
    any of them
}