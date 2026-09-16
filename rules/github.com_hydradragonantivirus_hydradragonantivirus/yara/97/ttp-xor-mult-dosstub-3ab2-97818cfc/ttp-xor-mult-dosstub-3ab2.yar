rule TTP_XOR_MULT_DOSStub_3ab2 {
  strings:
    $key_3ab2 = { 6e da [2] 1a c2 [2] 5d c0 [2] 1a d1 [2] 54 dd [2] 58 d7 [2] 4f dc [2] 54 92 [2] 69 }

  condition:
    any of them
}