rule TTP_XOR_MULT_DOSStub_bc34 {
  strings:
    $key_bc34 = { e8 5c [2] 9c 44 [2] db 46 [2] 9c 57 [2] d2 5b [2] de 51 [2] c9 5a [2] d2 14 [2] ef }

  condition:
    any of them
}