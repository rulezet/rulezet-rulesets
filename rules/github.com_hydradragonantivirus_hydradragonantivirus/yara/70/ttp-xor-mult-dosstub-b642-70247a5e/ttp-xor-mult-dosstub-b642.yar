rule TTP_XOR_MULT_DOSStub_b642 {
  strings:
    $key_b642 = { e2 2a [2] 96 32 [2] d1 30 [2] 96 21 [2] d8 2d [2] d4 27 [2] c3 2c [2] d8 62 [2] e5 }

  condition:
    any of them
}