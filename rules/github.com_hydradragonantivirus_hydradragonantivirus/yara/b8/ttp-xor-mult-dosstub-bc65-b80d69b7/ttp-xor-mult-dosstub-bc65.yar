rule TTP_XOR_MULT_DOSStub_bc65 {
  strings:
    $key_bc65 = { e8 0d [2] 9c 15 [2] db 17 [2] 9c 06 [2] d2 0a [2] de 00 [2] c9 0b [2] d2 45 [2] ef }

  condition:
    any of them
}