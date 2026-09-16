rule TTP_XOR_MULT_DOSStub_dedf {
  strings:
    $key_dedf = { 8a b7 [2] fe af [2] b9 ad [2] fe bc [2] b0 b0 [2] bc ba [2] ab b1 [2] b0 ff [2] 8d }

  condition:
    any of them
}