rule TTP_XOR_MULT_DOSStub_bed8 {
  strings:
    $key_bed8 = { ea b0 [2] 9e a8 [2] d9 aa [2] 9e bb [2] d0 b7 [2] dc bd [2] cb b6 [2] d0 f8 [2] ed }

  condition:
    any of them
}