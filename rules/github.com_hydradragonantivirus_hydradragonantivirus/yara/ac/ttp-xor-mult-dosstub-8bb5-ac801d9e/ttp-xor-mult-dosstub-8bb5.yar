rule TTP_XOR_MULT_DOSStub_8bb5 {
  strings:
    $key_8bb5 = { df dd [2] ab c5 [2] ec c7 [2] ab d6 [2] e5 da [2] e9 d0 [2] fe db [2] e5 95 [2] d8 }

  condition:
    any of them
}