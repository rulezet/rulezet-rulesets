rule TTP_XOR_MULT_DOSStub_b620 {
  strings:
    $key_b620 = { e2 48 [2] 96 50 [2] d1 52 [2] 96 43 [2] d8 4f [2] d4 45 [2] c3 4e [2] d8 00 [2] e5 }

  condition:
    any of them
}