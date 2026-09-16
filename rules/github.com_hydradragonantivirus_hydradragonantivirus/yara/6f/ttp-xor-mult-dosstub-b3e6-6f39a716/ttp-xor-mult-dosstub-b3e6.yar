rule TTP_XOR_MULT_DOSStub_b3e6 {
  strings:
    $key_b3e6 = { e7 8e [2] 93 96 [2] d4 94 [2] 93 85 [2] dd 89 [2] d1 83 [2] c6 88 [2] dd c6 [2] e0 }

  condition:
    any of them
}