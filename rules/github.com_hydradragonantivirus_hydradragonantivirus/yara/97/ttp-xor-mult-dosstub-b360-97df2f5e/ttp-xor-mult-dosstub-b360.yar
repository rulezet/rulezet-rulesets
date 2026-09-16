rule TTP_XOR_MULT_DOSStub_b360 {
  strings:
    $key_b360 = { e7 08 [2] 93 10 [2] d4 12 [2] 93 03 [2] dd 0f [2] d1 05 [2] c6 0e [2] dd 40 [2] e0 }

  condition:
    any of them
}