rule TTP_XOR_MULT_DOSStub_4711 {
  strings:
    $key_4711 = { 13 79 [2] 67 61 [2] 20 63 [2] 67 72 [2] 29 7e [2] 25 74 [2] 32 7f [2] 29 31 [2] 14 }

  condition:
    any of them
}