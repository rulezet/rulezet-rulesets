rule TTP_XOR_MULT_DOSStub_0d42 {
  strings:
    $key_0d42 = { 59 2a [2] 2d 32 [2] 6a 30 [2] 2d 21 [2] 63 2d [2] 6f 27 [2] 78 2c [2] 63 62 [2] 5e }

  condition:
    any of them
}