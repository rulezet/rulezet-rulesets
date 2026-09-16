rule TTP_XOR_MULT_DOSStub_4754 {
  strings:
    $key_4754 = { 13 3c [2] 67 24 [2] 20 26 [2] 67 37 [2] 29 3b [2] 25 31 [2] 32 3a [2] 29 74 [2] 14 }

  condition:
    any of them
}