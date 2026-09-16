rule TTP_XOR_MULT_DOSStub_b626 {
  strings:
    $key_b626 = { e2 4e [2] 96 56 [2] d1 54 [2] 96 45 [2] d8 49 [2] d4 43 [2] c3 48 [2] d8 06 [2] e5 }

  condition:
    any of them
}