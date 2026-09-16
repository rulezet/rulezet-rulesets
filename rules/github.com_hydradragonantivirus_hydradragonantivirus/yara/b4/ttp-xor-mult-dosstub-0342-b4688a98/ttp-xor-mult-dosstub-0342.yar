rule TTP_XOR_MULT_DOSStub_0342 {
  strings:
    $key_0342 = { 57 2a [2] 23 32 [2] 64 30 [2] 23 21 [2] 6d 2d [2] 61 27 [2] 76 2c [2] 6d 62 [2] 50 }

  condition:
    any of them
}