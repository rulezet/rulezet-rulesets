rule TTP_XOR_MULT_DOSStub_b650 {
  strings:
    $key_b650 = { e2 38 [2] 96 20 [2] d1 22 [2] 96 33 [2] d8 3f [2] d4 35 [2] c3 3e [2] d8 70 [2] e5 }

  condition:
    any of them
}