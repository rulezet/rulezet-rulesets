rule TTP_XOR_MULT_DOSStub_3ab5 {
  strings:
    $key_3ab5 = { 6e dd [2] 1a c5 [2] 5d c7 [2] 1a d6 [2] 54 da [2] 58 d0 [2] 4f db [2] 54 95 [2] 69 }

  condition:
    any of them
}