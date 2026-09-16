rule TTP_XOR_MULT_DOSStub_bc4a {
  strings:
    $key_bc4a = { e8 22 [2] 9c 3a [2] db 38 [2] 9c 29 [2] d2 25 [2] de 2f [2] c9 24 [2] d2 6a [2] ef }

  condition:
    any of them
}