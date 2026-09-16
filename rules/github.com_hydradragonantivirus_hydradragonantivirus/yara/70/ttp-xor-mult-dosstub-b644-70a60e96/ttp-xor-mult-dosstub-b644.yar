rule TTP_XOR_MULT_DOSStub_b644 {
  strings:
    $key_b644 = { e2 2c [2] 96 34 [2] d1 36 [2] 96 27 [2] d8 2b [2] d4 21 [2] c3 2a [2] d8 64 [2] e5 }

  condition:
    any of them
}