rule TTP_XOR_MULT_DOSStub_bc1a {
  strings:
    $key_bc1a = { e8 72 [2] 9c 6a [2] db 68 [2] 9c 79 [2] d2 75 [2] de 7f [2] c9 74 [2] d2 3a [2] ef }

  condition:
    any of them
}