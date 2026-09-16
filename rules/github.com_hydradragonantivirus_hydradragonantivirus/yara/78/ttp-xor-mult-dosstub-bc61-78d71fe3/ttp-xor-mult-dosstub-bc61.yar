rule TTP_XOR_MULT_DOSStub_bc61 {
  strings:
    $key_bc61 = { e8 09 [2] 9c 11 [2] db 13 [2] 9c 02 [2] d2 0e [2] de 04 [2] c9 0f [2] d2 41 [2] ef }

  condition:
    any of them
}