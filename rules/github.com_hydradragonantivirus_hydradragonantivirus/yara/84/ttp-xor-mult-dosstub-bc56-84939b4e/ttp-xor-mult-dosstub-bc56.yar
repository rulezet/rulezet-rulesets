rule TTP_XOR_MULT_DOSStub_bc56 {
  strings:
    $key_bc56 = { e8 3e [2] 9c 26 [2] db 24 [2] 9c 35 [2] d2 39 [2] de 33 [2] c9 38 [2] d2 76 [2] ef }

  condition:
    any of them
}