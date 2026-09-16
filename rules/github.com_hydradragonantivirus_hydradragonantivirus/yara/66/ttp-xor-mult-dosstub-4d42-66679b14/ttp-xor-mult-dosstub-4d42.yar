rule TTP_XOR_MULT_DOSStub_4d42 {
  strings:
    $key_4d42 = { 19 2a [2] 6d 32 [2] 2a 30 [2] 6d 21 [2] 23 2d [2] 2f 27 [2] 38 2c [2] 23 62 [2] 1e }

  condition:
    any of them
}