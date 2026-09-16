rule TTP_XOR_MULT_DOSStub_aedf {
  strings:
    $key_aedf = { fa b7 [2] 8e af [2] c9 ad [2] 8e bc [2] c0 b0 [2] cc ba [2] db b1 [2] c0 ff [2] fd }

  condition:
    any of them
}