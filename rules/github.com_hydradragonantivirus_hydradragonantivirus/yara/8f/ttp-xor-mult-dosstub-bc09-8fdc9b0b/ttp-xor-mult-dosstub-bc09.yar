rule TTP_XOR_MULT_DOSStub_bc09 {
  strings:
    $key_bc09 = { e8 61 [2] 9c 79 [2] db 7b [2] 9c 6a [2] d2 66 [2] de 6c [2] c9 67 [2] d2 29 [2] ef }

  condition:
    any of them
}