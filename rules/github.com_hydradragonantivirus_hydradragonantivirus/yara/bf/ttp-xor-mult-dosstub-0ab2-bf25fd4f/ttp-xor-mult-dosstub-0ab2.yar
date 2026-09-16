rule TTP_XOR_MULT_DOSStub_0ab2 {
  strings:
    $key_0ab2 = { 5e da [2] 2a c2 [2] 6d c0 [2] 2a d1 [2] 64 dd [2] 68 d7 [2] 7f dc [2] 64 92 [2] 59 }

  condition:
    any of them
}