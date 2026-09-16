rule TTP_XOR_MULT_DOSStub_1ab5 {
  strings:
    $key_1ab5 = { 4e dd [2] 3a c5 [2] 7d c7 [2] 3a d6 [2] 74 da [2] 78 d0 [2] 6f db [2] 74 95 [2] 49 }

  condition:
    any of them
}