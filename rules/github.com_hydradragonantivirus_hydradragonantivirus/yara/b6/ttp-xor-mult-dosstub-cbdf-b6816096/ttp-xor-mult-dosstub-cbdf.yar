rule TTP_XOR_MULT_DOSStub_cbdf {
  strings:
    $key_cbdf = { 9f b7 [2] eb af [2] ac ad [2] eb bc [2] a5 b0 [2] a9 ba [2] be b1 [2] a5 ff [2] 98 }

  condition:
    any of them
}