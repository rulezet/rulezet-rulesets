rule TTP_XOR_MULT_DOSStub_6342 {
  strings:
    $key_6342 = { 37 2a [2] 43 32 [2] 04 30 [2] 43 21 [2] 0d 2d [2] 01 27 [2] 16 2c [2] 0d 62 [2] 30 }

  condition:
    any of them
}