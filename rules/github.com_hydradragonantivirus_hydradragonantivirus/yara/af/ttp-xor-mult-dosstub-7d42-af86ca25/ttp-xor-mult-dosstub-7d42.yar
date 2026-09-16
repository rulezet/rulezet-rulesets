rule TTP_XOR_MULT_DOSStub_7d42 {
  strings:
    $key_7d42 = { 29 2a [2] 5d 32 [2] 1a 30 [2] 5d 21 [2] 13 2d [2] 1f 27 [2] 08 2c [2] 13 62 [2] 2e }

  condition:
    any of them
}