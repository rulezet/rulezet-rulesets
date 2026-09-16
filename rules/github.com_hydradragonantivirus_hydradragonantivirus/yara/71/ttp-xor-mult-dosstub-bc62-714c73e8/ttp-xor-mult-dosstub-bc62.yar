rule TTP_XOR_MULT_DOSStub_bc62 {
  strings:
    $key_bc62 = { e8 0a [2] 9c 12 [2] db 10 [2] 9c 01 [2] d2 0d [2] de 07 [2] c9 0c [2] d2 42 [2] ef }

  condition:
    any of them
}