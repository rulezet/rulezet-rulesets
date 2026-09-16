rule TTP_XOR_MULT_DOSStub_65b0 {
  strings:
    $key_65b0 = { 31 d8 [2] 45 c0 [2] 02 c2 [2] 45 d3 [2] 0b df [2] 07 d5 [2] 10 de [2] 0b 90 [2] 36 }

  condition:
    any of them
}