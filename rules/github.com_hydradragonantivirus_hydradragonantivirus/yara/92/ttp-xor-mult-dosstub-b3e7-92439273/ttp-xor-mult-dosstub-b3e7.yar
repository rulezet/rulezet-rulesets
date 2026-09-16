rule TTP_XOR_MULT_DOSStub_b3e7 {
  strings:
    $key_b3e7 = { e7 8f [2] 93 97 [2] d4 95 [2] 93 84 [2] dd 88 [2] d1 82 [2] c6 89 [2] dd c7 [2] e0 }

  condition:
    any of them
}