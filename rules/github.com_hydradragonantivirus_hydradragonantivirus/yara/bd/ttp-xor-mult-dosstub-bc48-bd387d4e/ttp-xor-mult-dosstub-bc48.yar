rule TTP_XOR_MULT_DOSStub_bc48 {
  strings:
    $key_bc48 = { e8 20 [2] 9c 38 [2] db 3a [2] 9c 2b [2] d2 27 [2] de 2d [2] c9 26 [2] d2 68 [2] ef }

  condition:
    any of them
}