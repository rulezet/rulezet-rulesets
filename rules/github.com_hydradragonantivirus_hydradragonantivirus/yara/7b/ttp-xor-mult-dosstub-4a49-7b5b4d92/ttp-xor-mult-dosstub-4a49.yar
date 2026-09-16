rule TTP_XOR_MULT_DOSStub_4a49 {
  strings:
    $key_4a49 = { 1e 21 [2] 6a 39 [2] 2d 3b [2] 6a 2a [2] 24 26 [2] 28 2c [2] 3f 27 [2] 24 69 [2] 19 }

  condition:
    any of them
}