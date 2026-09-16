rule TTP_XOR_MULT_DOSStub_1234 {
  strings:
    $key_1234 = { 46 5c [2] 32 44 [2] 75 46 [2] 32 57 [2] 7c 5b [2] 70 51 [2] 67 5a [2] 7c 14 [2] 41 }

  condition:
    any of them
}