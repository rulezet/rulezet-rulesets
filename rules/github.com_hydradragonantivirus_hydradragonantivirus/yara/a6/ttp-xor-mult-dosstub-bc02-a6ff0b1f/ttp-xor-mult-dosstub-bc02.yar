rule TTP_XOR_MULT_DOSStub_bc02 {
  strings:
    $key_bc02 = { e8 6a [2] 9c 72 [2] db 70 [2] 9c 61 [2] d2 6d [2] de 67 [2] c9 6c [2] d2 22 [2] ef }

  condition:
    any of them
}