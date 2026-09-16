rule TTP_XOR_MULT_DOSStub_5d42 {
  strings:
    $key_5d42 = { 09 2a [2] 7d 32 [2] 3a 30 [2] 7d 21 [2] 33 2d [2] 3f 27 [2] 28 2c [2] 33 62 [2] 0e }

  condition:
    any of them
}