rule TTP_XOR_MULT_DOSStub_bcfc {
  strings:
    $key_bcfc = { e8 94 [2] 9c 8c [2] db 8e [2] 9c 9f [2] d2 93 [2] de 99 [2] c9 92 [2] d2 dc [2] ef }

  condition:
    any of them
}