rule TTP_XOR_MULT_DOSStub_a9b0 {
  strings:
    $key_a9b0 = { fd d8 [2] 89 c0 [2] ce c2 [2] 89 d3 [2] c7 df [2] cb d5 [2] dc de [2] c7 90 [2] fa }

  condition:
    any of them
}