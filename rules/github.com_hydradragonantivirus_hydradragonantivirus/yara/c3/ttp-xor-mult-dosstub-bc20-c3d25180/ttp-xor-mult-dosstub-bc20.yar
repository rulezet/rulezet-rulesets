rule TTP_XOR_MULT_DOSStub_bc20 {
  strings:
    $key_bc20 = { e8 48 [2] 9c 50 [2] db 52 [2] 9c 43 [2] d2 4f [2] de 45 [2] c9 4e [2] d2 00 [2] ef }

  condition:
    any of them
}