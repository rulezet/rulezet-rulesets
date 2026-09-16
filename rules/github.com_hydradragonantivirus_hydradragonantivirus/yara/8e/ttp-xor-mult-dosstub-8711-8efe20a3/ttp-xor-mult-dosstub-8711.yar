rule TTP_XOR_MULT_DOSStub_8711 {
  strings:
    $key_8711 = { d3 79 [2] a7 61 [2] e0 63 [2] a7 72 [2] e9 7e [2] e5 74 [2] f2 7f [2] e9 31 [2] d4 }

  condition:
    any of them
}