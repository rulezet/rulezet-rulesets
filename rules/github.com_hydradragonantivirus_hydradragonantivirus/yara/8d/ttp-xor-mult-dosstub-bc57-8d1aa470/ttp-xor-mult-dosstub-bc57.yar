rule TTP_XOR_MULT_DOSStub_bc57 {
  strings:
    $key_bc57 = { e8 3f [2] 9c 27 [2] db 25 [2] 9c 34 [2] d2 38 [2] de 32 [2] c9 39 [2] d2 77 [2] ef }

  condition:
    any of them
}