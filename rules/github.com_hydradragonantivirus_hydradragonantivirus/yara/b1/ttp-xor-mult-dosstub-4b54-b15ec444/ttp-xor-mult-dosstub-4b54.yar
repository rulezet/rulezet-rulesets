rule TTP_XOR_MULT_DOSStub_4b54 {
  strings:
    $key_4b54 = { 1f 3c [2] 6b 24 [2] 2c 26 [2] 6b 37 [2] 25 3b [2] 29 31 [2] 3e 3a [2] 25 74 [2] 18 }

  condition:
    any of them
}