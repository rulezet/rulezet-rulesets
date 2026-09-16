rule TTP_XOR_MULT_DOSStub_b627 {
  strings:
    $key_b627 = { e2 4f [2] 96 57 [2] d1 55 [2] 96 44 [2] d8 48 [2] d4 42 [2] c3 49 [2] d8 07 [2] e5 }

  condition:
    any of them
}