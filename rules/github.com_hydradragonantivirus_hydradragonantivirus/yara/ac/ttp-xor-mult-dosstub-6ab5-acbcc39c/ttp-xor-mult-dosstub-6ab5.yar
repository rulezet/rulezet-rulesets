rule TTP_XOR_MULT_DOSStub_6ab5 {
  strings:
    $key_6ab5 = { 3e dd [2] 4a c5 [2] 0d c7 [2] 4a d6 [2] 04 da [2] 08 d0 [2] 1f db [2] 04 95 [2] 39 }

  condition:
    any of them
}