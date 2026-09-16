rule TTP_XOR_MULT_DOSStub_8bb1 {
  strings:
    $key_8bb1 = { df d9 [2] ab c1 [2] ec c3 [2] ab d2 [2] e5 de [2] e9 d4 [2] fe df [2] e5 91 [2] d8 }

  condition:
    any of them
}