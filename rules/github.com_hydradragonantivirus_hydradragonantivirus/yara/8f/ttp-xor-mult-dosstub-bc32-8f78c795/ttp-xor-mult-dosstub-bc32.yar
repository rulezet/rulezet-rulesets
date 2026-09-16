rule TTP_XOR_MULT_DOSStub_bc32 {
  strings:
    $key_bc32 = { e8 5a [2] 9c 42 [2] db 40 [2] 9c 51 [2] d2 5d [2] de 57 [2] c9 5c [2] d2 12 [2] ef }

  condition:
    any of them
}