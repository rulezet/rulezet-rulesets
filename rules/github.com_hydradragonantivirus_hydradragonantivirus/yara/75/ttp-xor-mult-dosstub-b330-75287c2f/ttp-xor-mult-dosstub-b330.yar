rule TTP_XOR_MULT_DOSStub_b330 {
  strings:
    $key_b330 = { e7 58 [2] 93 40 [2] d4 42 [2] 93 53 [2] dd 5f [2] d1 55 [2] c6 5e [2] dd 10 [2] e0 }

  condition:
    any of them
}