rule TTP_XOR_MULT_DOSStub_1042 {
  strings:
    $key_1042 = { 44 2a [2] 30 32 [2] 77 30 [2] 30 21 [2] 7e 2d [2] 72 27 [2] 65 2c [2] 7e 62 [2] 43 }

  condition:
    any of them
}