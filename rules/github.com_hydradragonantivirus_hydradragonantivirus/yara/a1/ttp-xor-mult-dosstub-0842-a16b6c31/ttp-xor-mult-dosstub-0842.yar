rule TTP_XOR_MULT_DOSStub_0842 {
  strings:
    $key_0842 = { 5c 2a [2] 28 32 [2] 6f 30 [2] 28 21 [2] 66 2d [2] 6a 27 [2] 7d 2c [2] 66 62 [2] 5b }

  condition:
    any of them
}