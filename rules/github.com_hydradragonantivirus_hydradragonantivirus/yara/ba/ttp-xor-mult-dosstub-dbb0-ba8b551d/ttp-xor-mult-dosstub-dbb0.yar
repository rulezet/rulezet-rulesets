rule TTP_XOR_MULT_DOSStub_dbb0 {
  strings:
    $key_dbb0 = { 8f d8 [2] fb c0 [2] bc c2 [2] fb d3 [2] b5 df [2] b9 d5 [2] ae de [2] b5 90 [2] 88 }

  condition:
    any of them
}