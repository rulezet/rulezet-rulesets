rule TTP_XOR_MULT_DOSStub_b542 {
  strings:
    $key_b542 = { e1 2a [2] 95 32 [2] d2 30 [2] 95 21 [2] db 2d [2] d7 27 [2] c0 2c [2] db 62 [2] e6 }

  condition:
    any of them
}