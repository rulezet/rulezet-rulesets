rule TTP_XOR_MULT_DOSStub_bc4e {
  strings:
    $key_bc4e = { e8 26 [2] 9c 3e [2] db 3c [2] 9c 2d [2] d2 21 [2] de 2b [2] c9 20 [2] d2 6e [2] ef }

  condition:
    any of them
}