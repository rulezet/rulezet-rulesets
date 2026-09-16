rule TTP_XOR_MULT_DOSStub_f8b0 {
  strings:
    $key_f8b0 = { ac d8 [2] d8 c0 [2] 9f c2 [2] d8 d3 [2] 96 df [2] 9a d5 [2] 8d de [2] 96 90 [2] ab }

  condition:
    any of them
}