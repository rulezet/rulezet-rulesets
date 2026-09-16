rule TTP_XOR_MULT_DOSStub_b3f0 {
  strings:
    $key_b3f0 = { e7 98 [2] 93 80 [2] d4 82 [2] 93 93 [2] dd 9f [2] d1 95 [2] c6 9e [2] dd d0 [2] e0 }

  condition:
    any of them
}