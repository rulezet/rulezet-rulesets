rule TTP_XOR_MULT_DOSStub_b340 {
  strings:
    $key_b340 = { e7 28 [2] 93 30 [2] d4 32 [2] 93 23 [2] dd 2f [2] d1 25 [2] c6 2e [2] dd 60 [2] e0 }

  condition:
    any of them
}