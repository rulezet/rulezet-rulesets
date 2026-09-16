rule TTP_XOR_MULT_DOSStub_4a44 {
  strings:
    $key_4a44 = { 1e 2c [2] 6a 34 [2] 2d 36 [2] 6a 27 [2] 24 2b [2] 28 21 [2] 3f 2a [2] 24 64 [2] 19 }

  condition:
    any of them
}