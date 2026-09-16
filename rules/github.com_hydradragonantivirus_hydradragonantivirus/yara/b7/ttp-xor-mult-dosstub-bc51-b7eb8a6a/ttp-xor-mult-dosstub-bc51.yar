rule TTP_XOR_MULT_DOSStub_bc51 {
  strings:
    $key_bc51 = { e8 39 [2] 9c 21 [2] db 23 [2] 9c 32 [2] d2 3e [2] de 34 [2] c9 3f [2] d2 71 [2] ef }

  condition:
    any of them
}