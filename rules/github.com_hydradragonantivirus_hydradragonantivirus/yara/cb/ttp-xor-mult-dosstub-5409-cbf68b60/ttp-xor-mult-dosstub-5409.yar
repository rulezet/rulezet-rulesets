rule TTP_XOR_MULT_DOSStub_5409 {
  strings:
    $key_5409 = { 00 61 [2] 74 79 [2] 33 7b [2] 74 6a [2] 3a 66 [2] 36 6c [2] 21 67 [2] 3a 29 [2] 07 }

  condition:
    any of them
}