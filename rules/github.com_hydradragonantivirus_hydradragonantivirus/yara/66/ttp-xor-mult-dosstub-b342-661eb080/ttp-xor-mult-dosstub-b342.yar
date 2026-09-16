rule TTP_XOR_MULT_DOSStub_b342 {
  strings:
    $key_b342 = { e7 2a [2] 93 32 [2] d4 30 [2] 93 21 [2] dd 2d [2] d1 27 [2] c6 2c [2] dd 62 [2] e0 }

  condition:
    any of them
}