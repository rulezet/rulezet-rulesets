rule TTP_XOR_MULT_DOSStub_b331 {
  strings:
    $key_b331 = { e7 59 [2] 93 41 [2] d4 43 [2] 93 52 [2] dd 5e [2] d1 54 [2] c6 5f [2] dd 11 [2] e0 }

  condition:
    any of them
}