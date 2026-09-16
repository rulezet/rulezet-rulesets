rule TTP_XOR_MULT_DOSStub_8bdf {
  strings:
    $key_8bdf = { df b7 [2] ab af [2] ec ad [2] ab bc [2] e5 b0 [2] e9 ba [2] fe b1 [2] e5 ff [2] d8 }

  condition:
    any of them
}