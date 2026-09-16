rule TTP_XOR_MULT_DOSStub_c8b0 {
  strings:
    $key_c8b0 = { 9c d8 [2] e8 c0 [2] af c2 [2] e8 d3 [2] a6 df [2] aa d5 [2] bd de [2] a6 90 [2] 9b }

  condition:
    any of them
}