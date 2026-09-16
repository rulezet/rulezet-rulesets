rule TTP_XOR_MULT_DOSStub_2a54 {
  strings:
    $key_2a54 = { 7e 3c [2] 0a 24 [2] 4d 26 [2] 0a 37 [2] 44 3b [2] 48 31 [2] 5f 3a [2] 44 74 [2] 79 }

  condition:
    any of them
}