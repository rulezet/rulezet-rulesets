rule TTP_XOR_MULT_DOSStub_2642 {
  strings:
    $key_2642 = { 72 2a [2] 06 32 [2] 41 30 [2] 06 21 [2] 48 2d [2] 44 27 [2] 53 2c [2] 48 62 [2] 75 }

  condition:
    any of them
}