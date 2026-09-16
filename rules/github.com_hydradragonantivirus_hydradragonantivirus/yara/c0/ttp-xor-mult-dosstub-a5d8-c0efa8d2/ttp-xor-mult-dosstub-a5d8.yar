rule TTP_XOR_MULT_DOSStub_a5d8 {
  strings:
    $key_a5d8 = { f1 b0 [2] 85 a8 [2] c2 aa [2] 85 bb [2] cb b7 [2] c7 bd [2] d0 b6 [2] cb f8 [2] f6 }

  condition:
    any of them
}