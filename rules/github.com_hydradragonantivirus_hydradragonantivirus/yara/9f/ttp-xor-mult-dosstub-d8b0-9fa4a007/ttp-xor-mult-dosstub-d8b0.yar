rule TTP_XOR_MULT_DOSStub_d8b0 {
  strings:
    $key_d8b0 = { 8c d8 [2] f8 c0 [2] bf c2 [2] f8 d3 [2] b6 df [2] ba d5 [2] ad de [2] b6 90 [2] 8b }

  condition:
    any of them
}