rule TTP_XOR_MULT_DOSStub_beca {
  strings:
    $key_beca = { ea a2 [2] 9e ba [2] d9 b8 [2] 9e a9 [2] d0 a5 [2] dc af [2] cb a4 [2] d0 ea [2] ed }

  condition:
    any of them
}