rule TTP_XOR_MULT_DOSStub_bc01 {
  strings:
    $key_bc01 = { e8 69 [2] 9c 71 [2] db 73 [2] 9c 62 [2] d2 6e [2] de 64 [2] c9 6f [2] d2 21 [2] ef }

  condition:
    any of them
}