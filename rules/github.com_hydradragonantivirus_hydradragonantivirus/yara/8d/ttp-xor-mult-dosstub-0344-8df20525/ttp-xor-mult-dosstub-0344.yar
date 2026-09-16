rule TTP_XOR_MULT_DOSStub_0344 {
  strings:
    $key_0344 = { 57 2c [2] 23 34 [2] 64 36 [2] 23 27 [2] 6d 2b [2] 61 21 [2] 76 2a [2] 6d 64 [2] 50 }

  condition:
    any of them
}