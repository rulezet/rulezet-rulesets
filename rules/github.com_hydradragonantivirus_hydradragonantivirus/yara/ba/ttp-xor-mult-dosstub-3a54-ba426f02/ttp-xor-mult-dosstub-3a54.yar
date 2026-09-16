rule TTP_XOR_MULT_DOSStub_3a54 {
  strings:
    $key_3a54 = { 6e 3c [2] 1a 24 [2] 5d 26 [2] 1a 37 [2] 54 3b [2] 58 31 [2] 4f 3a [2] 54 74 [2] 69 }

  condition:
    any of them
}