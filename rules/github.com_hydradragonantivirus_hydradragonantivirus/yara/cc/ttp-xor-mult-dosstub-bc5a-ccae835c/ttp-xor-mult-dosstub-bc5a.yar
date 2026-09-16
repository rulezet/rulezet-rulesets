rule TTP_XOR_MULT_DOSStub_bc5a {
  strings:
    $key_bc5a = { e8 32 [2] 9c 2a [2] db 28 [2] 9c 39 [2] d2 35 [2] de 3f [2] c9 34 [2] d2 7a [2] ef }

  condition:
    any of them
}