rule TTP_XOR_MULT_DOSStub_0711 {
  strings:
    $key_0711 = { 53 79 [2] 27 61 [2] 60 63 [2] 27 72 [2] 69 7e [2] 65 74 [2] 72 7f [2] 69 31 [2] 54 }

  condition:
    any of them
}