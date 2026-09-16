rule TTP_XOR_MULT_DOSStub_0ab5 {
  strings:
    $key_0ab5 = { 5e dd [2] 2a c5 [2] 6d c7 [2] 2a d6 [2] 64 da [2] 68 d0 [2] 7f db [2] 64 95 [2] 59 }

  condition:
    any of them
}