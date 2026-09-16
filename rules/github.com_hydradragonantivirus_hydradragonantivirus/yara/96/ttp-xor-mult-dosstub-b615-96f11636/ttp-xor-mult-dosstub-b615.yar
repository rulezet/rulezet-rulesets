rule TTP_XOR_MULT_DOSStub_b615 {
  strings:
    $key_b615 = { e2 7d [2] 96 65 [2] d1 67 [2] 96 76 [2] d8 7a [2] d4 70 [2] c3 7b [2] d8 35 [2] e5 }

  condition:
    any of them
}