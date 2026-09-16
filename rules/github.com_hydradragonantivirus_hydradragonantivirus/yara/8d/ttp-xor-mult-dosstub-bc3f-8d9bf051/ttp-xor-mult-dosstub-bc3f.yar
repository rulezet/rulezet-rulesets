rule TTP_XOR_MULT_DOSStub_bc3f {
  strings:
    $key_bc3f = { e8 57 [2] 9c 4f [2] db 4d [2] 9c 5c [2] d2 50 [2] de 5a [2] c9 51 [2] d2 1f [2] ef }

  condition:
    any of them
}