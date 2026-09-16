rule TTP_XOR_MULT_DOSStub_e8b0 {
  strings:
    $key_e8b0 = { bc d8 [2] c8 c0 [2] 8f c2 [2] c8 d3 [2] 86 df [2] 8a d5 [2] 9d de [2] 86 90 [2] bb }

  condition:
    any of them
}