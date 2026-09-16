rule TTP_XOR_MULT_DOSStub_bc06 {
  strings:
    $key_bc06 = { e8 6e [2] 9c 76 [2] db 74 [2] 9c 65 [2] d2 69 [2] de 63 [2] c9 68 [2] d2 26 [2] ef }

  condition:
    any of them
}