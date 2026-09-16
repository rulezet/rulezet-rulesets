rule TTP_XOR_MULT_DOSStub_1049 {
  strings:
    $key_1049 = { 44 21 [2] 30 39 [2] 77 3b [2] 30 2a [2] 7e 26 [2] 72 2c [2] 65 27 [2] 7e 69 [2] 43 }

  condition:
    any of them
}