rule TTP_XOR_MULT_DOSStub_bed4 {
  strings:
    $key_bed4 = { ea bc [2] 9e a4 [2] d9 a6 [2] 9e b7 [2] d0 bb [2] dc b1 [2] cb ba [2] d0 f4 [2] ed }

  condition:
    any of them
}