rule TTP_XOR_MULT_DOSStub_8bb0 {
  strings:
    $key_8bb0 = { df d8 [2] ab c0 [2] ec c2 [2] ab d3 [2] e5 df [2] e9 d5 [2] fe de [2] e5 90 [2] d8 }

  condition:
    any of them
}