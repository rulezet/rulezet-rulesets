rule TTP_XOR_MULT_DOSStub_bc68 {
  strings:
    $key_bc68 = { e8 00 [2] 9c 18 [2] db 1a [2] 9c 0b [2] d2 07 [2] de 0d [2] c9 06 [2] d2 48 [2] ef }

  condition:
    any of them
}