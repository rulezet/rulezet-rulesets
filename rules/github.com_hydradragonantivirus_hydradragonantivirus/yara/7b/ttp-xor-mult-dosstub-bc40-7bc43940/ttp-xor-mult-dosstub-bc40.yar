rule TTP_XOR_MULT_DOSStub_bc40 {
  strings:
    $key_bc40 = { e8 28 [2] 9c 30 [2] db 32 [2] 9c 23 [2] d2 2f [2] de 25 [2] c9 2e [2] d2 60 [2] ef }

  condition:
    any of them
}