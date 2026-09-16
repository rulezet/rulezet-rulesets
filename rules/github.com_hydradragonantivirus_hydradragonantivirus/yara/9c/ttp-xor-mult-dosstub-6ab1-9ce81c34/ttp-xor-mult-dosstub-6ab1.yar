rule TTP_XOR_MULT_DOSStub_6ab1 {
  strings:
    $key_6ab1 = { 3e d9 [2] 4a c1 [2] 0d c3 [2] 4a d2 [2] 04 de [2] 08 d4 [2] 1f df [2] 04 91 [2] 39 }

  condition:
    any of them
}