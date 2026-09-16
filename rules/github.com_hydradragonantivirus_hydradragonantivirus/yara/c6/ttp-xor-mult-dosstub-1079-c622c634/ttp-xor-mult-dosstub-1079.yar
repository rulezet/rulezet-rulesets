rule TTP_XOR_MULT_DOSStub_1079 {
  strings:
    $key_1079 = { 44 11 [2] 30 09 [2] 77 0b [2] 30 1a [2] 7e 16 [2] 72 1c [2] 65 17 [2] 7e 59 [2] 43 }

  condition:
    any of them
}