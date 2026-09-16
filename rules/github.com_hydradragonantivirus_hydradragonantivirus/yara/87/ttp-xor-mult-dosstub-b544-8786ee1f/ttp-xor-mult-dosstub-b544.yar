rule TTP_XOR_MULT_DOSStub_b544 {
  strings:
    $key_b544 = { e1 2c [2] 95 34 [2] d2 36 [2] 95 27 [2] db 2b [2] d7 21 [2] c0 2a [2] db 64 [2] e6 }

  condition:
    any of them
}