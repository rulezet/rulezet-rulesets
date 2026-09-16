rule TTP_XOR_MULT_DOSStub_4442 {
  strings:
    $key_4442 = { 10 2a [2] 64 32 [2] 23 30 [2] 64 21 [2] 2a 2d [2] 26 27 [2] 31 2c [2] 2a 62 [2] 17 }

  condition:
    any of them
}