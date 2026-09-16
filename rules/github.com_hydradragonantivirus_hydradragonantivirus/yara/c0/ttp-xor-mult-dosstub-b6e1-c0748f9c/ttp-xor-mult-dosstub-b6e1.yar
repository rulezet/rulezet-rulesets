rule TTP_XOR_MULT_DOSStub_b6e1 {
  strings:
    $key_b6e1 = { e2 89 [2] 96 91 [2] d1 93 [2] 96 82 [2] d8 8e [2] d4 84 [2] c3 8f [2] d8 c1 [2] e5 }

  condition:
    any of them
}