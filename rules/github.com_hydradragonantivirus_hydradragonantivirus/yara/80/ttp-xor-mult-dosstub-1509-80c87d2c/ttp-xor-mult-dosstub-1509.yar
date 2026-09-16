rule TTP_XOR_MULT_DOSStub_1509 {
  strings:
    $key_1509 = { 41 61 [2] 35 79 [2] 72 7b [2] 35 6a [2] 7b 66 [2] 77 6c [2] 60 67 [2] 7b 29 [2] 46 }

  condition:
    any of them
}