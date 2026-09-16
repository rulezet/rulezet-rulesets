rule TTP_XOR_MULT_DOSStub_f711 {
  strings:
    $key_f711 = { a3 79 [2] d7 61 [2] 90 63 [2] d7 72 [2] 99 7e [2] 95 74 [2] 82 7f [2] 99 31 [2] a4 }

  condition:
    any of them
}