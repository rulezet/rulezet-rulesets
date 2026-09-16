rule TTP_XOR_MULT_DOSStub_4154 {
  strings:
    $key_4154 = { 15 3c [2] 61 24 [2] 26 26 [2] 61 37 [2] 2f 3b [2] 23 31 [2] 34 3a [2] 2f 74 [2] 12 }

  condition:
    any of them
}