rule TTP_XOR_MULT_DOSStub_bcf1 {
  strings:
    $key_bcf1 = { e8 99 [2] 9c 81 [2] db 83 [2] 9c 92 [2] d2 9e [2] de 94 [2] c9 9f [2] d2 d1 [2] ef }

  condition:
    any of them
}