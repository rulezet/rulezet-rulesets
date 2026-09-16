rule TTP_XOR_MULT_DOSStub_8bb4 {
  strings:
    $key_8bb4 = { df dc [2] ab c4 [2] ec c6 [2] ab d7 [2] e5 db [2] e9 d1 [2] fe da [2] e5 94 [2] d8 }

  condition:
    any of them
}