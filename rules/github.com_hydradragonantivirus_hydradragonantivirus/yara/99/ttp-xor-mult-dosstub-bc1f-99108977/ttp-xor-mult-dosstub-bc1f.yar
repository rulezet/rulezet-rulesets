rule TTP_XOR_MULT_DOSStub_bc1f {
  strings:
    $key_bc1f = { e8 77 [2] 9c 6f [2] db 6d [2] 9c 7c [2] d2 70 [2] de 7a [2] c9 71 [2] d2 3f [2] ef }

  condition:
    any of them
}