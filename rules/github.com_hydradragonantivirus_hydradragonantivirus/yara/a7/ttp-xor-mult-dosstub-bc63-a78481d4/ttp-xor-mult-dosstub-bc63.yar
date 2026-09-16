rule TTP_XOR_MULT_DOSStub_bc63 {
  strings:
    $key_bc63 = { e8 0b [2] 9c 13 [2] db 11 [2] 9c 00 [2] d2 0c [2] de 06 [2] c9 0d [2] d2 43 [2] ef }

  condition:
    any of them
}