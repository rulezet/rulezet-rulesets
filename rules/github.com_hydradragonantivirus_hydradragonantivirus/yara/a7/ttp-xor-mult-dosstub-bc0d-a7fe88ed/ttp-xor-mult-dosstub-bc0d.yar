rule TTP_XOR_MULT_DOSStub_bc0d {
  strings:
    $key_bc0d = { e8 65 [2] 9c 7d [2] db 7f [2] 9c 6e [2] d2 62 [2] de 68 [2] c9 63 [2] d2 2d [2] ef }

  condition:
    any of them
}