rule TTP_XOR_MULT_DOSStub_bc55 {
  strings:
    $key_bc55 = { e8 3d [2] 9c 25 [2] db 27 [2] 9c 36 [2] d2 3a [2] de 30 [2] c9 3b [2] d2 75 [2] ef }

  condition:
    any of them
}