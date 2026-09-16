rule TTP_XOR_MULT_DOSStub_bc11 {
  strings:
    $key_bc11 = { e8 79 [2] 9c 61 [2] db 63 [2] 9c 72 [2] d2 7e [2] de 74 [2] c9 7f [2] d2 31 [2] ef }

  condition:
    any of them
}