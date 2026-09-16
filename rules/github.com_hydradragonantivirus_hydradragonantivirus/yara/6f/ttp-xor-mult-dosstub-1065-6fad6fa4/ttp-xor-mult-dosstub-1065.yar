rule TTP_XOR_MULT_DOSStub_1065 {
  strings:
    $key_1065 = { 44 0d [2] 30 15 [2] 77 17 [2] 30 06 [2] 7e 0a [2] 72 00 [2] 65 0b [2] 7e 45 [2] 43 }

  condition:
    any of them
}