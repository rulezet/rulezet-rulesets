rule TTP_XOR_MULT_DOSStub_4a54 {
  strings:
    $key_4a54 = { 1e 3c [2] 6a 24 [2] 2d 26 [2] 6a 37 [2] 24 3b [2] 28 31 [2] 3f 3a [2] 24 74 [2] 19 }

  condition:
    any of them
}