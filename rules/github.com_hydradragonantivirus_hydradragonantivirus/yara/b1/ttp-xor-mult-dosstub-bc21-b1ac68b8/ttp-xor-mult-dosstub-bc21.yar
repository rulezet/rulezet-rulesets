rule TTP_XOR_MULT_DOSStub_bc21 {
  strings:
    $key_bc21 = { e8 49 [2] 9c 51 [2] db 53 [2] 9c 42 [2] d2 4e [2] de 44 [2] c9 4f [2] d2 01 [2] ef }

  condition:
    any of them
}