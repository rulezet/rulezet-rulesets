rule TTP_XOR_MULT_DOSStub_bc31 {
  strings:
    $key_bc31 = { e8 59 [2] 9c 41 [2] db 43 [2] 9c 52 [2] d2 5e [2] de 54 [2] c9 5f [2] d2 11 [2] ef }

  condition:
    any of them
}