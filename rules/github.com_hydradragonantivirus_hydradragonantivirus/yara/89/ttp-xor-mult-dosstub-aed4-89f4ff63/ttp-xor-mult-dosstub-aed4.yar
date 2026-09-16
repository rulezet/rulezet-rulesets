rule TTP_XOR_MULT_DOSStub_aed4 {
  strings:
    $key_aed4 = { fa bc [2] 8e a4 [2] c9 a6 [2] 8e b7 [2] c0 bb [2] cc b1 [2] db ba [2] c0 f4 [2] fd }

  condition:
    any of them
}