rule TTP_XOR_MULT_DOSStub_bed0 {
  strings:
    $key_bed0 = { ea b8 [2] 9e a0 [2] d9 a2 [2] 9e b3 [2] d0 bf [2] dc b5 [2] cb be [2] d0 f0 [2] ed }

  condition:
    any of them
}