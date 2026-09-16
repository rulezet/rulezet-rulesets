rule TTP_XOR_MULT_DOSStub_b026 {
  strings:
    $key_b026 = { e4 4e [2] 90 56 [2] d7 54 [2] 90 45 [2] de 49 [2] d2 43 [2] c5 48 [2] de 06 [2] e3 }

  condition:
    any of them
}