rule TTP_XOR_MULT_DOSStub_a8b0 {
  strings:
    $key_a8b0 = { fc d8 [2] 88 c0 [2] cf c2 [2] 88 d3 [2] c6 df [2] ca d5 [2] dd de [2] c6 90 [2] fb }

  condition:
    any of them
}