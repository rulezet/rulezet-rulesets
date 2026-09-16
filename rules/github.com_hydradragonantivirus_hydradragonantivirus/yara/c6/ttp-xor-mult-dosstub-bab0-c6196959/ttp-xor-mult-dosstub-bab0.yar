rule TTP_XOR_MULT_DOSStub_bab0 {
  strings:
    $key_bab0 = { ee d8 [2] 9a c0 [2] dd c2 [2] 9a d3 [2] d4 df [2] d8 d5 [2] cf de [2] d4 90 [2] e9 }

  condition:
    any of them
}