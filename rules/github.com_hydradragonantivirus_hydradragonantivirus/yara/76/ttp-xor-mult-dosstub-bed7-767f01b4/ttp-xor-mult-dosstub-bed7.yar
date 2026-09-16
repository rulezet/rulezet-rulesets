rule TTP_XOR_MULT_DOSStub_bed7 {
  strings:
    $key_bed7 = { ea bf [2] 9e a7 [2] d9 a5 [2] 9e b4 [2] d0 b8 [2] dc b2 [2] cb b9 [2] d0 f7 [2] ed }

  condition:
    any of them
}