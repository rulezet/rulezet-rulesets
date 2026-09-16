rule TTP_XOR_MULT_DOSStub_7b54 {
  strings:
    $key_7b54 = { 2f 3c [2] 5b 24 [2] 1c 26 [2] 5b 37 [2] 15 3b [2] 19 31 [2] 0e 3a [2] 15 74 [2] 28 }

  condition:
    any of them
}