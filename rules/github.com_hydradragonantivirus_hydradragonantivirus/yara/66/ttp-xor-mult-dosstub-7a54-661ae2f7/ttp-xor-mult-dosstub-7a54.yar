rule TTP_XOR_MULT_DOSStub_7a54 {
  strings:
    $key_7a54 = { 2e 3c [2] 5a 24 [2] 1d 26 [2] 5a 37 [2] 14 3b [2] 18 31 [2] 0f 3a [2] 14 74 [2] 29 }

  condition:
    any of them
}