rule TTP_XOR_MULT_DOSStub_bc46 {
  strings:
    $key_bc46 = { e8 2e [2] 9c 36 [2] db 34 [2] 9c 25 [2] d2 29 [2] de 23 [2] c9 28 [2] d2 66 [2] ef }

  condition:
    any of them
}