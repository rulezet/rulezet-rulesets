rule TTP_XOR_MULT_DOSStub_bc05 {
  strings:
    $key_bc05 = { e8 6d [2] 9c 75 [2] db 77 [2] 9c 66 [2] d2 6a [2] de 60 [2] c9 6b [2] d2 25 [2] ef }

  condition:
    any of them
}