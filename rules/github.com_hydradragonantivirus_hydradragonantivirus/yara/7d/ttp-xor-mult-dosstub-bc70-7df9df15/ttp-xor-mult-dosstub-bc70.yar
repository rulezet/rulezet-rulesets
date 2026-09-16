rule TTP_XOR_MULT_DOSStub_bc70 {
  strings:
    $key_bc70 = { e8 18 [2] 9c 00 [2] db 02 [2] 9c 13 [2] d2 1f [2] de 15 [2] c9 1e [2] d2 50 [2] ef }

  condition:
    any of them
}