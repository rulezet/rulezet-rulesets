rule TTP_XOR_MULT_DOSStub_1034 {
  strings:
    $key_1034 = { 44 5c [2] 30 44 [2] 77 46 [2] 30 57 [2] 7e 5b [2] 72 51 [2] 65 5a [2] 7e 14 [2] 43 }

  condition:
    any of them
}