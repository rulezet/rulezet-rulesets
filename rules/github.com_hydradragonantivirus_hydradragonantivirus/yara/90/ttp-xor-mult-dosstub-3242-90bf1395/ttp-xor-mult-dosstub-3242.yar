rule TTP_XOR_MULT_DOSStub_3242 {
  strings:
    $key_3242 = { 66 2a [2] 12 32 [2] 55 30 [2] 12 21 [2] 5c 2d [2] 50 27 [2] 47 2c [2] 5c 62 [2] 61 }

  condition:
    any of them
}