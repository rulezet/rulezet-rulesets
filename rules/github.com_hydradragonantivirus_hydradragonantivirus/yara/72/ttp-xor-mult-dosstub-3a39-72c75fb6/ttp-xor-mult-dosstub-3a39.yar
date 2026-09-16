rule TTP_XOR_MULT_DOSStub_3a39 {
  strings:
    $key_3a39 = { 6e 51 [2] 1a 49 [2] 5d 4b [2] 1a 5a [2] 54 56 [2] 58 5c [2] 4f 57 [2] 54 19 [2] 69 }

  condition:
    any of them
}