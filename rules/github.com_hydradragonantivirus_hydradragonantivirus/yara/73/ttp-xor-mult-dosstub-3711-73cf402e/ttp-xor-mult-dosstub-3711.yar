rule TTP_XOR_MULT_DOSStub_3711 {
  strings:
    $key_3711 = { 63 79 [2] 17 61 [2] 50 63 [2] 17 72 [2] 59 7e [2] 55 74 [2] 42 7f [2] 59 31 [2] 64 }

  condition:
    any of them
}