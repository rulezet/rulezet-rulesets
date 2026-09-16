rule TTP_XOR_MULT_DOSStub_bc72 {
  strings:
    $key_bc72 = { e8 1a [2] 9c 02 [2] db 00 [2] 9c 11 [2] d2 1d [2] de 17 [2] c9 1c [2] d2 52 [2] ef }

  condition:
    any of them
}