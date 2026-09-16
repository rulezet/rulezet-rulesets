rule TTP_XOR_MULT_DOSStub_cadf {
  strings:
    $key_cadf = { 9e b7 [2] ea af [2] ad ad [2] ea bc [2] a4 b0 [2] a8 ba [2] bf b1 [2] a4 ff [2] 99 }

  condition:
    any of them
}