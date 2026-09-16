rule TTP_XOR_MULT_DOSStub_7ab2 {
  strings:
    $key_7ab2 = { 2e da [2] 5a c2 [2] 1d c0 [2] 5a d1 [2] 14 dd [2] 18 d7 [2] 0f dc [2] 14 92 [2] 29 }

  condition:
    any of them
}