rule TTP_XOR_MULT_DOSStub_bc60 {
  strings:
    $key_bc60 = { e8 08 [2] 9c 10 [2] db 12 [2] 9c 03 [2] d2 0f [2] de 05 [2] c9 0e [2] d2 40 [2] ef }

  condition:
    any of them
}