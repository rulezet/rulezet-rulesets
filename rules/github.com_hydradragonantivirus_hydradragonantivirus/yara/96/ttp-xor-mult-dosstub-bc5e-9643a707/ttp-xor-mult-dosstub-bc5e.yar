rule TTP_XOR_MULT_DOSStub_bc5e {
  strings:
    $key_bc5e = { e8 36 [2] 9c 2e [2] db 2c [2] 9c 3d [2] d2 31 [2] de 3b [2] c9 30 [2] d2 7e [2] ef }

  condition:
    any of them
}