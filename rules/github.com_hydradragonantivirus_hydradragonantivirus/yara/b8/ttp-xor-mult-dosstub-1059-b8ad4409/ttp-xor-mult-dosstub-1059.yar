rule TTP_XOR_MULT_DOSStub_1059 {
  strings:
    $key_1059 = { 44 31 [2] 30 29 [2] 77 2b [2] 30 3a [2] 7e 36 [2] 72 3c [2] 65 37 [2] 7e 79 [2] 43 }

  condition:
    any of them
}