rule TTP_XOR_MULT_DOSStub_8bb2 {
  strings:
    $key_8bb2 = { df da [2] ab c2 [2] ec c0 [2] ab d1 [2] e5 dd [2] e9 d7 [2] fe dc [2] e5 92 [2] d8 }

  condition:
    any of them
}