rule TTP_XOR_MULT_DOSStub_0b54 {
  strings:
    $key_0b54 = { 5f 3c [2] 2b 24 [2] 6c 26 [2] 2b 37 [2] 65 3b [2] 69 31 [2] 7e 3a [2] 65 74 [2] 58 }

  condition:
    any of them
}