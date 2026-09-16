rule TTP_XOR_MULT_DOSStub_b657 {
  strings:
    $key_b657 = { e2 3f [2] 96 27 [2] d1 25 [2] 96 34 [2] d8 38 [2] d4 32 [2] c3 39 [2] d8 77 [2] e5 }

  condition:
    any of them
}