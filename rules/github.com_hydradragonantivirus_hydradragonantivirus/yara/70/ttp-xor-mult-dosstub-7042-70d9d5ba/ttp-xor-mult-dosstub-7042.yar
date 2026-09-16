rule TTP_XOR_MULT_DOSStub_7042 {
  strings:
    $key_7042 = { 24 2a [2] 50 32 [2] 17 30 [2] 50 21 [2] 1e 2d [2] 12 27 [2] 05 2c [2] 1e 62 [2] 23 }

  condition:
    any of them
}