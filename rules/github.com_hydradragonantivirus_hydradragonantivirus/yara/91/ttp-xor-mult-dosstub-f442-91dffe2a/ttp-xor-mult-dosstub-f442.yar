rule TTP_XOR_MULT_DOSStub_f442 {
  strings:
    $key_f442 = { a0 2a [2] d4 32 [2] 93 30 [2] d4 21 [2] 9a 2d [2] 96 27 [2] 81 2c [2] 9a 62 [2] a7 }

  condition:
    any of them
}