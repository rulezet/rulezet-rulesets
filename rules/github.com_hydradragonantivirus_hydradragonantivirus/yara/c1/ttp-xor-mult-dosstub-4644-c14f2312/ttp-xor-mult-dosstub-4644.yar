rule TTP_XOR_MULT_DOSStub_4644 {
  strings:
    $key_4644 = { 12 2c [2] 66 34 [2] 21 36 [2] 66 27 [2] 28 2b [2] 24 21 [2] 33 2a [2] 28 64 [2] 15 }

  condition:
    any of them
}