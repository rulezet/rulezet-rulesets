rule TTP_XOR_MULT_DOSStub_b361 {
  strings:
    $key_b361 = { e7 09 [2] 93 11 [2] d4 13 [2] 93 02 [2] dd 0e [2] d1 04 [2] c6 0f [2] dd 41 [2] e0 }

  condition:
    any of them
}