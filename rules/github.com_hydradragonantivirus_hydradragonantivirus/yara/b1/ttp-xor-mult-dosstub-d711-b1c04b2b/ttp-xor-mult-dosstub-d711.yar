rule TTP_XOR_MULT_DOSStub_d711 {
  strings:
    $key_d711 = { 83 79 [2] f7 61 [2] b0 63 [2] f7 72 [2] b9 7e [2] b5 74 [2] a2 7f [2] b9 31 [2] 84 }

  condition:
    any of them
}