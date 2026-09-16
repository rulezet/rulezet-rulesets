rule TTP_XOR_MULT_DOSStub_f8b6 {
  strings:
    $key_f8b6 = { ac de [2] d8 c6 [2] 9f c4 [2] d8 d5 [2] 96 d9 [2] 9a d3 [2] 8d d8 [2] 96 96 [2] ab }

  condition:
    any of them
}