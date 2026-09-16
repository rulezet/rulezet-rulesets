rule TTP_XOR_MULT_DOSStub_bc77 {
  strings:
    $key_bc77 = { e8 1f [2] 9c 07 [2] db 05 [2] 9c 14 [2] d2 18 [2] de 12 [2] c9 19 [2] d2 57 [2] ef }

  condition:
    any of them
}