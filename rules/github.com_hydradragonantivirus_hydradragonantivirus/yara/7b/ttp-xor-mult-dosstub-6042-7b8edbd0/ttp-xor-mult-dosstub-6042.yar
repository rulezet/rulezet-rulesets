rule TTP_XOR_MULT_DOSStub_6042 {
  strings:
    $key_6042 = { 34 2a [2] 40 32 [2] 07 30 [2] 40 21 [2] 0e 2d [2] 02 27 [2] 15 2c [2] 0e 62 [2] 33 }

  condition:
    any of them
}