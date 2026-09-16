rule TTP_XOR_MULT_DOSStub_3554 {
  strings:
    $key_3554 = { 61 3c [2] 15 24 [2] 52 26 [2] 15 37 [2] 5b 3b [2] 57 31 [2] 40 3a [2] 5b 74 [2] 66 }

  condition:
    any of them
}