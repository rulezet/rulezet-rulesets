rule TTP_XOR_MULT_DOSStub_bc18 {
  strings:
    $key_bc18 = { e8 70 [2] 9c 68 [2] db 6a [2] 9c 7b [2] d2 77 [2] de 7d [2] c9 76 [2] d2 38 [2] ef }

  condition:
    any of them
}