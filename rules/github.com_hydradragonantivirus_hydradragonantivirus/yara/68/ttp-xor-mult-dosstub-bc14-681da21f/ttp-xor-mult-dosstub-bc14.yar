rule TTP_XOR_MULT_DOSStub_bc14 {
  strings:
    $key_bc14 = { e8 7c [2] 9c 64 [2] db 66 [2] 9c 77 [2] d2 7b [2] de 71 [2] c9 7a [2] d2 34 [2] ef }

  condition:
    any of them
}