rule TTP_XOR_MULT_DOSStub_bc26 {
  strings:
    $key_bc26 = { e8 4e [2] 9c 56 [2] db 54 [2] 9c 45 [2] d2 49 [2] de 43 [2] c9 48 [2] d2 06 [2] ef }

  condition:
    any of them
}