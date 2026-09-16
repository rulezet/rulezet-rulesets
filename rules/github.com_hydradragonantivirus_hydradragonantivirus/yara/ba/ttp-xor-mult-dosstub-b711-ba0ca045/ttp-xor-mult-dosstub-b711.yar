rule TTP_XOR_MULT_DOSStub_b711 {
  strings:
    $key_b711 = { e3 79 [2] 97 61 [2] d0 63 [2] 97 72 [2] d9 7e [2] d5 74 [2] c2 7f [2] d9 31 [2] e4 }

  condition:
    any of them
}