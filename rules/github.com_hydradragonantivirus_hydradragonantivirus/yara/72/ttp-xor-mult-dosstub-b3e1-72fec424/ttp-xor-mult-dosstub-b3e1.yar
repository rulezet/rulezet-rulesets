rule TTP_XOR_MULT_DOSStub_b3e1 {
  strings:
    $key_b3e1 = { e7 89 [2] 93 91 [2] d4 93 [2] 93 82 [2] dd 8e [2] d1 84 [2] c6 8f [2] dd c1 [2] e0 }

  condition:
    any of them
}