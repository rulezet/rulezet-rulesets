rule TTP_XOR_MULT_DOSStub_4a34 {
  strings:
    $key_4a34 = { 1e 5c [2] 6a 44 [2] 2d 46 [2] 6a 57 [2] 24 5b [2] 28 51 [2] 3f 5a [2] 24 14 [2] 19 }

  condition:
    any of them
}