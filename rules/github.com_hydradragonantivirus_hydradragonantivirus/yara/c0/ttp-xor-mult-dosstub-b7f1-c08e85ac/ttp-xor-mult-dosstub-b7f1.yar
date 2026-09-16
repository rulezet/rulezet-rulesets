rule TTP_XOR_MULT_DOSStub_b7f1 {
  strings:
    $key_b7f1 = { e3 99 [2] 97 81 [2] d0 83 [2] 97 92 [2] d9 9e [2] d5 94 [2] c2 9f [2] d9 d1 [2] e4 }

  condition:
    any of them
}