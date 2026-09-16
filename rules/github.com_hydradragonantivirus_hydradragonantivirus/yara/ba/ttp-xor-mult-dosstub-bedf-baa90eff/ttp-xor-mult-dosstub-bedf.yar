rule TTP_XOR_MULT_DOSStub_bedf {
  strings:
    $key_bedf = { ea b7 [2] 9e af [2] d9 ad [2] 9e bc [2] d0 b0 [2] dc ba [2] cb b1 [2] d0 ff [2] ed }

  condition:
    any of them
}