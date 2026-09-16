rule TTP_XOR_MULT_DOSStub_bc59 {
  strings:
    $key_bc59 = { e8 31 [2] 9c 29 [2] db 2b [2] 9c 3a [2] d2 36 [2] de 3c [2] c9 37 [2] d2 79 [2] ef }

  condition:
    any of them
}