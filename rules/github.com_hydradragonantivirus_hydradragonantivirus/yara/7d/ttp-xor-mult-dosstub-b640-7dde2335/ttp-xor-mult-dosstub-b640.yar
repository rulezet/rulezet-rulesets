rule TTP_XOR_MULT_DOSStub_b640 {
  strings:
    $key_b640 = { e2 28 [2] 96 30 [2] d1 32 [2] 96 23 [2] d8 2f [2] d4 25 [2] c3 2e [2] d8 60 [2] e5 }

  condition:
    any of them
}