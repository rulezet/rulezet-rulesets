rule TTP_XOR_MULT_DOSStub_4a39 {
  strings:
    $key_4a39 = { 1e 51 [2] 6a 49 [2] 2d 4b [2] 6a 5a [2] 24 56 [2] 28 5c [2] 3f 57 [2] 24 19 [2] 19 }

  condition:
    any of them
}