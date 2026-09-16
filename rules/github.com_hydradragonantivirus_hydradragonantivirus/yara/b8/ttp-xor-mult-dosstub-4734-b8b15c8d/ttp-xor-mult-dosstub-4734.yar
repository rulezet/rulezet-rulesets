rule TTP_XOR_MULT_DOSStub_4734 {
  strings:
    $key_4734 = { 13 5c [2] 67 44 [2] 20 46 [2] 67 57 [2] 29 5b [2] 25 51 [2] 32 5a [2] 29 14 [2] 14 }

  condition:
    any of them
}