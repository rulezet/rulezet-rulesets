rule TTP_XOR_MULT_DOSStub_b6f6 {
  strings:
    $key_b6f6 = { e2 9e [2] 96 86 [2] d1 84 [2] 96 95 [2] d8 99 [2] d4 93 [2] c3 98 [2] d8 d6 [2] e5 }

  condition:
    any of them
}