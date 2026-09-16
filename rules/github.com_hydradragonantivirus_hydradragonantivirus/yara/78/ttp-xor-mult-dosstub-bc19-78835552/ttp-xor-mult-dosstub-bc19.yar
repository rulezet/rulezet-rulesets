rule TTP_XOR_MULT_DOSStub_bc19 {
  strings:
    $key_bc19 = { e8 71 [2] 9c 69 [2] db 6b [2] 9c 7a [2] d2 76 [2] de 7c [2] c9 77 [2] d2 39 [2] ef }

  condition:
    any of them
}