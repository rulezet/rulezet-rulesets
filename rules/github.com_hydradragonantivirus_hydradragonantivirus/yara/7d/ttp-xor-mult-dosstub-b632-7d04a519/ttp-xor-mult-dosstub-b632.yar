rule TTP_XOR_MULT_DOSStub_b632 {
  strings:
    $key_b632 = { e2 5a [2] 96 42 [2] d1 40 [2] 96 51 [2] d8 5d [2] d4 57 [2] c3 5c [2] d8 12 [2] e5 }

  condition:
    any of them
}