rule TTP_XOR_MULT_DOSStub_2ab1 {
  strings:
    $key_2ab1 = { 7e d9 [2] 0a c1 [2] 4d c3 [2] 0a d2 [2] 44 de [2] 48 d4 [2] 5f df [2] 44 91 [2] 79 }

  condition:
    any of them
}