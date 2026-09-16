rule TTP_XOR_MULT_DOSStub_4a59 {
  strings:
    $key_4a59 = { 1e 31 [2] 6a 29 [2] 2d 2b [2] 6a 3a [2] 24 36 [2] 28 3c [2] 3f 37 [2] 24 79 [2] 19 }

  condition:
    any of them
}