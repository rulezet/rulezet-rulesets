rule TTP_XOR_MULT_DOSStub_b376 {
  strings:
    $key_b376 = { e7 1e [2] 93 06 [2] d4 04 [2] 93 15 [2] dd 19 [2] d1 13 [2] c6 18 [2] dd 56 [2] e0 }

  condition:
    any of them
}