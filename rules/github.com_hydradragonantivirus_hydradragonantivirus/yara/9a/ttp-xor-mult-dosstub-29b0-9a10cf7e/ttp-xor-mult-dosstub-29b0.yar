rule TTP_XOR_MULT_DOSStub_29b0 {
  strings:
    $key_29b0 = { 7d d8 [2] 09 c0 [2] 4e c2 [2] 09 d3 [2] 47 df [2] 4b d5 [2] 5c de [2] 47 90 [2] 7a }

  condition:
    any of them
}