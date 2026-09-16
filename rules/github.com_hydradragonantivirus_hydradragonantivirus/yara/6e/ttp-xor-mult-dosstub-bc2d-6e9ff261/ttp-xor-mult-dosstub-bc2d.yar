rule TTP_XOR_MULT_DOSStub_bc2d {
  strings:
    $key_bc2d = { e8 45 [2] 9c 5d [2] db 5f [2] 9c 4e [2] d2 42 [2] de 48 [2] c9 43 [2] d2 0d [2] ef }

  condition:
    any of them
}