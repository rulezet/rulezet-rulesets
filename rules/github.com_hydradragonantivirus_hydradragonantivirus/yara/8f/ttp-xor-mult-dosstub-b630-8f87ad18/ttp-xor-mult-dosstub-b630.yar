rule TTP_XOR_MULT_DOSStub_b630 {
  strings:
    $key_b630 = { e2 58 [2] 96 40 [2] d1 42 [2] 96 53 [2] d8 5f [2] d4 55 [2] c3 5e [2] d8 10 [2] e5 }

  condition:
    any of them
}