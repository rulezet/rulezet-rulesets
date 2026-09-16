rule TTP_XOR_MULT_DOSStub_0042 {
  strings:
    $key_0042 = { 54 2a [2] 20 32 [2] 67 30 [2] 20 21 [2] 6e 2d [2] 62 27 [2] 75 2c [2] 6e 62 [2] 53 }

  condition:
    any of them
}