rule TTP_XOR_MULT_DOSStub_57b6 {
  strings:
    $key_57b6 = { 03 de [2] 77 c6 [2] 30 c4 [2] 77 d5 [2] 39 d9 [2] 35 d3 [2] 22 d8 [2] 39 96 [2] 04 }

  condition:
    any of them
}