rule TTP_XOR_MULT_DOSStub_b051 {
  strings:
    $key_b051 = { e4 39 [2] 90 21 [2] d7 23 [2] 90 32 [2] de 3e [2] d2 34 [2] c5 3f [2] de 71 [2] e3 }

  condition:
    any of them
}