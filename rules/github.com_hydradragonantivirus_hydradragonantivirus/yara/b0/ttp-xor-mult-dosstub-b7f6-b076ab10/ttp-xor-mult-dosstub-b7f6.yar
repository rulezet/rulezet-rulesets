rule TTP_XOR_MULT_DOSStub_b7f6 {
  strings:
    $key_b7f6 = { e3 9e [2] 97 86 [2] d0 84 [2] 97 95 [2] d9 99 [2] d5 93 [2] c2 98 [2] d9 d6 [2] e4 }

  condition:
    any of them
}