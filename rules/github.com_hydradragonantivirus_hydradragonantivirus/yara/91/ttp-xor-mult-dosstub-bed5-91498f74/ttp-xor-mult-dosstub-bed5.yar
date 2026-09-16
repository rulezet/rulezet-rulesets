rule TTP_XOR_MULT_DOSStub_bed5 {
  strings:
    $key_bed5 = { ea bd [2] 9e a5 [2] d9 a7 [2] 9e b6 [2] d0 ba [2] dc b0 [2] cb bb [2] d0 f5 [2] ed }

  condition:
    any of them
}